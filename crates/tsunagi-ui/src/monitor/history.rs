//! A private scratch database belongs to one window and one worker thread.
//! A capture with millions of flows uses disk, and the UI reads one page at a time.
use super::{Column, Names, Sort};
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, params, params_from_iter, types::Value};
use std::{path::Path, sync::Arc};
use tsunagi::traffic::{Flow, FlowDelta, Role};

pub(super) const PAGE_SIZE: usize = 64;
pub(super) const RATE_LIFETIME_MS: u64 = 1900;
const RETAIN_MS: u64 = 60_000;

#[derive(Default, Clone, PartialEq)]
pub(super) struct Filter {
    pub network: Option<[u8; 32]>,
    pub peer: Option<[u8; 32]>,
    pub protocol: Option<u8>,
    pub role: Option<Role>,
    pub transport: bool,
    pub sort: Sort,
    pub before: Option<Cursor>,
}

#[derive(Clone, PartialEq)]
pub(super) struct Cursor {
    value: Value,
    id: i64,
}

pub(super) struct Row {
    order_value: Value,
    pub id: i64,
    pub data: FlowDelta,
    pub last: u64,
    pub sampled: u64,
    pub tx_rate: f32,
    pub rx_rate: f32,
}
impl Row {
    pub fn cursor(&self) -> Cursor {
        Cursor {
            value: self.order_value.clone(),
            id: self.id,
        }
    }
}
#[derive(Default)]
pub(super) struct Page {
    pub rows: Vec<Row>,
    pub more: bool,
}

pub(super) struct History {
    connection: Connection,
    indexed: Option<Column>,
    names: Arc<Names>,
}

// SQLite counters are signed 64-bit integers; clamp only at its representable maximum.
fn integer(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl History {
    pub fn open(directory: Option<&Path>) -> Result<Self, String> {
        // SQLite chooses a delete-on-close temp file on the desktop. Android supplies
        // its private writable cache directory (the system temp directory can be read-only).
        let file = directory
            .map(tempfile::NamedTempFile::new_in)
            .transpose()
            .map_err(|e| e.to_string())?;
        let path = file
            .as_ref()
            .map(|f| f.path())
            .unwrap_or_else(|| Path::new(""));
        let db = Connection::open(path).map_err(|e| e.to_string())?;
        db.execute_batch("PRAGMA locking_mode=EXCLUSIVE;
            PRAGMA journal_mode=OFF;
            PRAGMA synchronous=OFF;
            PRAGMA cache_size=-2048;
            CREATE TABLE flow (
              id INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB UNIQUE NOT NULL, network BLOB NOT NULL,
              peer BLOB NOT NULL, other BLOB, role INTEGER NOT NULL, protocol INTEGER, transport INTEGER NOT NULL,
              tx INTEGER NOT NULL, rx INTEGER NOT NULL, ntx INTEGER NOT NULL, nrx INTEGER NOT NULL,
              last INTEGER NOT NULL, sampled INTEGER NOT NULL, tx_rate REAL NOT NULL, rx_rate REAL NOT NULL
            );
            CREATE INDEX live_rates ON flow(sampled) WHERE tx_rate>0 OR rx_rate>0;
            CREATE INDEX by_last ON flow(last);
            CREATE INDEX by_layer ON flow(transport,id);
            CREATE INDEX by_network ON flow(transport,network,id);
            CREATE INDEX by_peer ON flow(transport,network,peer,id);
            CREATE INDEX by_other ON flow(transport,network,other,id) WHERE other IS NOT NULL;
            CREATE INDEX by_role ON flow(transport,role,id);
            CREATE INDEX by_protocol ON flow(transport,protocol,id);").map_err(|e|e.to_string())?;
        // All platforms that pass a directory are Unix; unlink the open file so even
        // force-stopping the activity releases it when the OS closes the descriptor.
        drop(file);
        Ok(Self {
            connection: db,
            indexed: None,
            names: Arc::default(),
        })
    }

    pub fn use_names(&mut self, names: Arc<Names>) {
        if !Arc::ptr_eq(&self.names, &names) {
            self.names = names;
            if self.indexed.is_some_and(Column::uses_names) {
                self.indexed = None;
            }
        }
    }

    // One index serves the active ordering, including its stable tie-breaker.
    // Long captures pay its setup cost once per change on the window worker.
    fn prepare_order(&mut self, column: Column) -> rusqlite::Result<()> {
        if self.indexed == Some(column) {
            return Ok(());
        }
        self.connection
            .execute_batch("DROP INDEX IF EXISTS by_view")?;
        let expr = column.sql();
        if expr == "flow_label(key)" {
            let names = self.names.clone();
            self.connection.create_scalar_function(
                "flow_label",
                1,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                move |ctx| {
                    let bytes = ctx.get_raw(0).as_blob()?;
                    let key = postcard::from_bytes(bytes)
                        .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
                    Ok(column.label_key(&key, &names))
                },
            )?;
        }
        self.connection.execute_batch(&format!(
            "CREATE INDEX by_view ON flow(transport,{expr},id)"
        ))?;
        self.indexed = Some(column);
        Ok(())
    }

    pub fn interrupt(&self) -> rusqlite::InterruptHandle {
        self.connection.get_interrupt_handle()
    }

    pub fn apply(
        &mut self,
        data: &[FlowDelta],
        now: u64,
        interval: u64,
        keep: bool,
    ) -> Result<(), String> {
        let txn = self.connection.transaction().map_err(|e| e.to_string())?;
        {
            let mut statement=txn.prepare_cached("INSERT INTO flow (key,network,peer,other,role,protocol,transport,tx,rx,ntx,nrx,last,sampled,tx_rate,rx_rate)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
            ON CONFLICT(key) DO UPDATE SET tx=min(9223372036854775807,tx+excluded.tx),rx=min(9223372036854775807,rx+excluded.rx),ntx=min(9223372036854775807,ntx+excluded.ntx),nrx=min(9223372036854775807,nrx+excluded.nrx),
            last=max(last,excluded.last), sampled=excluded.sampled,tx_rate=excluded.tx_rate,rx_rate=excluded.rx_rate").map_err(|e|e.to_string())?;
            let seconds = interval.max(1) as f64 / 1000.;
            for d in data {
                let key = postcard::to_stdvec(&d.key).map_err(|e| e.to_string())?;
                let (protocol, other) = match &d.key.flow {
                    Flow::Ip { protocol, .. } => (Some(*protocol), None),
                    Flow::Relay { other, .. } => (None, Some(other.as_slice())),
                    Flow::Control => (None, None),
                };
                statement
                    .execute(params![
                        key,
                        &d.key.network[..],
                        &d.key.peer[..],
                        other,
                        d.key.role as i64,
                        protocol,
                        d.key.role.transport(),
                        integer(d.tx_bytes),
                        integer(d.rx_bytes),
                        integer(d.tx_packets),
                        integer(d.rx_packets),
                        integer(now.saturating_sub(d.age_ms)),
                        integer(now),
                        d.tx_bytes as f64 / seconds,
                        d.rx_bytes as f64 / seconds
                    ])
                    .map_err(|e| e.to_string())?;
            }
        }
        if now >= RATE_LIFETIME_MS {
            txn.execute(
                "UPDATE flow SET tx_rate=0,rx_rate=0 WHERE sampled<=? AND (tx_rate>0 OR rx_rate>0)",
                [integer(now - RATE_LIFETIME_MS)],
            )
            .map_err(|e| e.to_string())?;
        }
        if !keep && now >= RETAIN_MS {
            txn.execute(
                "DELETE FROM flow WHERE last <= ?1",
                [integer(now - RETAIN_MS)],
            )
            .map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())
    }

    pub fn page(&mut self, f: &Filter) -> Result<Page, String> {
        self.prepare_order(f.sort.column)
            .map_err(|e| e.to_string())?;
        let expr = f.sort.column.sql();
        let mut sql = format!(
            "SELECT id,key,tx,rx,ntx,nrx,last,sampled,tx_rate,rx_rate,{expr} FROM flow WHERE transport=?"
        );
        let mut args = vec![Value::Integer(i64::from(f.transport))];
        if let Some(n) = f.network {
            sql.push_str(" AND network=?");
            args.push(Value::Blob(n.to_vec()));
        }
        if let Some(p) = f.peer {
            sql.push_str(" AND (peer=? OR other=?)");
            args.extend([Value::Blob(p.to_vec()), Value::Blob(p.to_vec())]);
        }
        if let Some(r) = f.role {
            sql.push_str(" AND role=?");
            args.push(Value::Integer(r as i64));
        }
        if let Some(p) = f.protocol {
            sql.push_str(" AND protocol=?");
            args.push(Value::Integer(p.into()));
        }
        let (op, direction) = if f.sort.descending {
            ("<", "DESC")
        } else {
            (">", "ASC")
        };
        if let Some(cursor) = &f.before {
            sql.push_str(&format!(" AND ({expr},id){op}(?,?)"));
            args.extend([cursor.value.clone(), Value::Integer(cursor.id)]);
        }
        sql.push_str(&format!(
            " ORDER BY {expr} {direction},id {direction} LIMIT ?"
        ));
        args.push(Value::Integer(PAGE_SIZE as i64 + 1));
        let mut q = self
            .connection
            .prepare_cached(&sql)
            .map_err(|e| e.to_string())?;
        let rows = q
            .query_map(params_from_iter(args), |r| {
                let blob: Vec<u8> = r.get(1)?;
                let key = postcard::from_bytes(&blob).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                Ok(Row {
                    id: r.get(0)?,
                    order_value: r.get(10)?,
                    data: FlowDelta {
                        key,
                        tx_bytes: r.get::<_, i64>(2)? as u64,
                        rx_bytes: r.get::<_, i64>(3)? as u64,
                        tx_packets: r.get::<_, i64>(4)? as u64,
                        rx_packets: r.get::<_, i64>(5)? as u64,
                        age_ms: 0,
                    },
                    last: r.get::<_, i64>(6)? as u64,
                    sampled: r.get::<_, i64>(7)? as u64,
                    tx_rate: r.get(8)?,
                    rx_rate: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        let mut page = Page {
            more: rows.len() > PAGE_SIZE,
            rows,
        };
        page.rows.truncate(PAGE_SIZE);
        Ok(page)
    }
}
