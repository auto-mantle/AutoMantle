use super::{
    Context, Observation, Request, RequestMonitor, Result, credential_response, reply,
    stream_response, writes_body,
};
use std::io::{Read, Write};

pub(super) fn forward_observed(
    client: &mut (impl Write + RequestMonitor),
    upstream: &mut (impl Read + Write),
    request: &Request,
    context: &Context,
    secure: bool,
    mut observation: Option<&mut Observation>,
) -> Result<()> {
    if let Some(event) = observation.as_deref_mut()
        && !event.request_active(client)
    {
        return Ok(());
    }
    if !context.active() {
        return Ok(());
    }
    if !context.credentials.is_current() {
        if let Some(event) = observation.as_deref_mut() {
            event.report("CREDENTIAL_BINDING_DENIED");
        }
        return reply(client, 403, "credential changed; retry the request");
    }
    let plan = match request.credential_plan(&context.credentials) {
        Ok(plan) => plan,
        Err(_) => return reply(client, 403, "invalid credential placement"),
    };
    let authenticated = !plan.is_empty();
    if !context.credentials.permits(
        &plan,
        &context.profile,
        &request.host,
        &request.method,
        &request.path,
        secure,
    ) {
        if let Some(event) = observation.as_deref_mut() {
            event.report("CREDENTIAL_BINDING_DENIED");
        }
        return reply(client, 403, "credential scope denied");
    }
    let output = match crate::injection::materialize(
        &request.injection_input(),
        &context.credentials,
        &plan,
    ) {
        Ok(output) => output,
        Err(_) => {
            if let Some(event) = observation.as_deref_mut() {
                event.report("CREDENTIAL_BINDING_DENIED");
            }
            return reply(client, 403, "credential changed or could not be inserted");
        }
    };
    let mut outgoing = request.clone();
    outgoing.headers = output.headers;
    outgoing.target = output.target;
    if let Some(body) = output.body {
        outgoing.body = body;
    }
    let request = &outgoing;
    eprintln!(
        "network decision=allow method={} host={}",
        request.method, request.host
    );
    if let Some(event) = observation.as_deref_mut() {
        if !event.request_active(client) {
            return Ok(());
        }
        if let Some(authorization) = event.authorization.as_mut() {
            authorization.dispatched();
        }
    }
    write_upstream_request(upstream, request, context, &plan)?;
    send_upstream_response(
        client,
        upstream,
        request,
        context,
        authenticated,
        observation,
    )
}

fn write_upstream_request(
    upstream: &mut impl Write,
    request: &Request,
    context: &Context,
    plan: &[crate::injection::Placement],
) -> Result<()> {
    let authenticated = !plan.is_empty();
    write!(
        upstream,
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        request.method, request.target, request.host
    )?;
    for (name, value) in &request.headers {
        if [
            "host",
            "connection",
            "proxy-connection",
            "content-length",
            "content-type",
            "expect",
            "transfer-encoding",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        if authenticated && name == "accept-encoding" {
            continue;
        }
        if matches!(name.as_str(), "authorization" | "x-api-key")
            && !plan
                .iter()
                .any(|placement| placement.location == "header" && placement.selector == *name)
        {
            let replacement = context
                .credentials
                .forward_guest_token(name, value)
                .ok_or("credential replacement unavailable")?;
            write!(upstream, "{name}: {replacement}\r\n")?;
        } else {
            write!(upstream, "{name}: {value}\r\n")?;
        }
    }
    if authenticated {
        upstream.write_all(b"Accept-Encoding: identity\r\n")?;
    }
    if writes_body(&request.method) {
        if !request.content_type.is_empty() {
            write!(upstream, "Content-Type: {}\r\n", request.content_type)?;
        }
        write!(upstream, "Content-Length: {}\r\n", request.body.len())?;
    }
    upstream.write_all(b"Connection: close\r\n\r\n")?;
    upstream.write_all(&request.body)?;
    upstream.flush()?;
    Ok(())
}

fn send_upstream_response(
    client: &mut impl Write,
    upstream: &mut impl Read,
    request: &Request,
    context: &Context,
    authenticated: bool,
    observation: Option<&mut Observation>,
) -> Result<()> {
    if authenticated {
        let (response, decoded) =
            match credential_response(upstream, &request.method, &|| context.active()) {
                Ok(response) => response,
                Err(_) => {
                    if let Some(event) = observation {
                        event.report("RESPONSE_BLOCKED");
                    }
                    return reply(client, 502, "credential response framing failed");
                }
            };
        if !context.active() {
            return Ok(());
        }
        if context.credentials.contains_secret(&response)
            || context.credentials.contains_secret(&decoded)
        {
            if let Some(event) = observation {
                event.report("RESPONSE_BLOCKED");
            }
            return reply(client, 502, "credential response blocked");
        }
        crate::body::copy_exact(&mut &*response, client, response.len() as u64, &|| {
            context.active()
        })?;
        client.flush()?;
        return Ok(());
    }
    stream_response(client, upstream, &request.method, || context.active())
}
