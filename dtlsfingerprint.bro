@load base/files/x509
@load base/protocols/ssl

module dtlsparse;

export {
    redef enum Log::ID += { LOG };

    type Info: record{
        version:     count         &log &optional; 
        ciphers:     index_vec     &log &optional;
        cextensions: set[count]    &log &optional;
        ecurves:     index_vec     &log &optional;
        cipher:      count         &log &optional;
        curve:       count         &log &optional;
        compmethod:  count         &log &optional;
        sextensions: set[count]    &log &optional;
        validity:    interval      &log &optional; 
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
    l$cextensions=set();
    l$sextensions=set();
    return l;
    }

function log_record(info: Info)
    {
      Log::write(dtlsparse::LOG, info);
    }

function finish(c: connection)
    {
    local l:Info;
    if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 || ! c$ssl$cert_chain[0]?$x509 ){
        l=c$dtls;
        log_record(l);
    }
    else{
        local cert = c$ssl$cert_chain[0]$x509$certificate;
        l=c$dtls;
        l$validity = cert$not_valid_after-cert$not_valid_before;
        log_record(l);
    }
    }

event bro_init()
    {
    Log::create_stream(dtlsparse::LOG,[$columns=dtlsparse::Info,$ev=log_dtls,$path="dtls"]);
    }

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
    {
    if(version == 65279 || version == 65277){
        local l = set_session(version);
        l$ciphers=ciphers;
        c$dtls=l; 
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
        else{
            local d = set_session(version);
            d$cipher = cipher;
            d$compmethod = comp_method;
            c$dtls=d;
        }
    }
    }

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    local l: Info;
    if(c?$dtls){
        l=c$dtls;
        if(is_orig){
            add l$cextensions[code];
        }
        else{
            add l$sextensions[code];
        }
        c$dtls=l;
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

