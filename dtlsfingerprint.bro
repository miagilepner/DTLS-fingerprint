@load base/files/x509
@load base/protocols/ssl

module dtlsparse;

export {
    redef enum Log::ID += { LOG };

    type Info: record{
        ts:          time          &log &optional;
        #formatted time stamp
        fts:         string        &log &optional;
        uid:         string        &log &optional;
        version:     count         &log &optional; 
        ciphers:     index_vec     &log &optional;
        cextensions: index_vec     &log &optional;
        ecurves:     index_vec     &log &optional;
        cipher:      count         &log &optional;
        curve:       count         &log &optional;
        compmethod:  count         &log &optional;
        sextensions: index_vec     &log &optional;
        validity:    interval      &log &optional; 
        cfingerprint:string        &log &optional;
    };
    global log_dtls: event(rec: Info);
    }

redef record connection +={
      dtls: Info &optional;
    };


function set_session(version: count): Info 
    {
    local l:Info;
    l$version=version;
    l$cextensions=vector();
    l$sextensions=vector();
    return l;
    }

function log_record(info: Info)
    {
    Log::write(dtlsparse::LOG, info);
    }

# Return a client DTLS fingerprint similar to this form:
# https://github.com/majek/p0f/blob/6b1570c6caf8e6c4de0d67e72eb6892030223b01/docs/README#L716
# In the "sslver" field we use a string like "DTLSv1.0".
function make_client_fingerprint(dtls: Info): string
    {
    local ciphers_hex: vector of string;
    local cextensions_hex: vector of string;
    local flags: vector of string;
    for (i in dtls$ciphers) {
        ciphers_hex[i] = fmt("%x", dtls$ciphers[i]);
    }
    for (i in dtls$cextensions) {
        cextensions_hex[i] = fmt("%x", dtls$cextensions[i]);
    }
    if (dtls$compmethod == 1) {
        flags[|flags|] = "compr";
    }
    return cat_sep(":", "",
        SSL::version_strings[dtls$version],
        join_string_vec(ciphers_hex, ","),
        join_string_vec(cextensions_hex, ","),
        join_string_vec(flags, ","));
    }

function finish(c: connection)
    {
    local l:Info;
    l=c$dtls;
    l$cfingerprint = make_client_fingerprint(l);
    if(c?$conn){
      l$uid = c$conn$uid;
      l$ts = c$conn$ts;
      l$fts = strftime("%FT%T",c$conn$ts);
    }
    if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 ){
        log_record(l);
    }
    else{
        local cert = c$ssl$cert_chain[0]$x509$certificate;
        l$validity = cert$not_valid_after-cert$not_valid_before;
    }
    log_record(l);
    }

event bro_init()
    {
    Log::create_stream(dtlsparse::LOG,[$columns=dtlsparse::Info,$ev=log_dtls,$path="dtls"]);
    }

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
    {
    if(version == 65279 || version == 65277){
        if(!c?$dtls){
            local l = set_session(version);
            l$ciphers=ciphers;
            c$dtls=l;
        } 
    } 
    }

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
    {
    if(version == 65279 || version == 65277){
        if(c?$dtls){
            local l: Info;
            l = c$dtls; 
            l$cipher=cipher;
            l$compmethod = comp_method;
            c$dtls=l;
        }
    }
    }

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if(c?$dtls){
        if(is_orig){
            #local l: Info; 
            #l=c$dtls;
            #add l$cextensions[code];
            #c$dtls=l;
            c$dtls$cextensions[|c$dtls$cextensions|] = code;
        }
        else{
            #local i: Info; 
            #i=c$dtls;
            #add i$sextensions[code];
            #c$dtls=i;
            c$dtls$sextensions[|c$dtls$sextensions|] = code;
        }
    }
    }

event ssl_established(c: connection)
    {
        if(c?$dtls){
          finish(c);
        }
    }
event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
    {
        if(c?$dtls){
          finish(c);
        }
    }

event connection_state_remove(c: connection)
    {
        if(c?$dtls){
            finish(c);
        }
    }

