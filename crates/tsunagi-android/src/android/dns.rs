//! Android's physical-network resolver, including its Private DNS policy.
use crate::dns::Resolver;
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JByteArray, JString, JValue},
};
use simple_dns::{CLASS, Packet, PacketFlag, QTYPE, RCODE, ResourceRecord, TYPE, rdata::RData};
use std::{net::IpAddr, sync::Arc};

pub(super) fn resolver(vm: Arc<JavaVM>, service: GlobalRef, sdk: i32) -> Resolver {
    Resolver::new(move |query| {
        let mut env = vm.attach_current_thread().ok()?;
        let response = env.with_local_frame(6, |env| {
            if sdk < 29 {
                return legacy(env, &service, query);
            }
            let bytes = env.byte_array_from_slice(query)?;
            let reply = env
                .call_method(&service, "resolveDns", "([B)[B", &[JValue::Object(&bytes)])?
                .l()?;
            if reply.is_null() {
                return Ok(None);
            }
            let reply = JByteArray::from(reply);
            if env.get_array_length(&reply)? > i32::from(u16::MAX) {
                return Ok(None);
            }
            env.convert_byte_array(reply).map(Some)
        });
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
            return None;
        }
        response.ok().flatten()
    })
}

fn legacy(
    env: &mut JNIEnv<'_>,
    service: &GlobalRef,
    query: &[u8],
) -> jni::errors::Result<Option<Vec<u8>>> {
    let Some(packet) = Packet::parse(query).ok() else {
        return Ok(None);
    };
    let [question] = packet.questions.as_slice() else {
        return Ok(None);
    };
    let mut reply = Packet::new_reply(packet.id());
    reply.questions.push(question.clone());
    reply.set_flags(PacketFlag::RECURSION_AVAILABLE);
    if packet.has_flags(PacketFlag::RECURSION_DESIRED) {
        reply.set_flags(PacketFlag::RECURSION_DESIRED);
    }
    if matches!(question.qtype, QTYPE::TYPE(TYPE::A | TYPE::AAAA)) {
        let name = env.new_string(format!("{}.", question.qname))?;
        let addresses = env
            .call_method(
                service,
                "resolveAddresses",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(&name)],
            )?
            .l()?;
        if addresses.is_null() {
            return Ok(None);
        }
        let addresses: String = env.get_string(&JString::from(addresses))?.into();
        for address in addresses
            .split(',')
            .take(128)
            .filter_map(|s| s.parse::<IpAddr>().ok())
        {
            let data = match (question.qtype, address) {
                (QTYPE::TYPE(TYPE::A), IpAddr::V4(v4)) => RData::A(v4.into()),
                (QTYPE::TYPE(TYPE::AAAA), IpAddr::V6(v6)) => RData::AAAA(v6.into()),
                _ => continue,
            };
            reply.answers.push(ResourceRecord::new(
                question.qname.clone(),
                CLASS::IN,
                0,
                data,
            ));
        }
    } else {
        *reply.rcode_mut() = RCODE::NotImplemented;
    }
    Ok(reply.build_bytes_vec_compressed().ok())
}
