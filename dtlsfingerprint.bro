@load base/files/x509
@load base/protocols/ssl

module dtlsparse;

redef record SSL::Info += {
    # These are numeric versions of SSL::Info's $version and $cipher,
    # which are resolved into strings.
    numversion:  count     &optional;
    numcipher:   count     &optional;
    numcurve:    count     &optional;

    ciphers:     index_vec &optional;
    cextensions: index_vec &optional;
    ecurves:     index_vec &optional;
    compmethod:  count     &optional;
    sextensions: index_vec &optional;
};

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:          time          &log &optional;
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

function log_record(info: Info)
    {
    Log::write(dtlsparse::LOG, info);
    }

# Return a client DTLS fingerprint similar to this form:
# https://github.com/majek/p0f/blob/6b1570c6caf8e6c4de0d67e72eb6892030223b01/docs/README#L716
# In the "sslver" field we use a string like "DTLSv1.0".
function make_client_fingerprint(ssl: SSL::Info): string
    {
    local ciphers_hex: vector of string;
    local cextensions_hex: vector of string;
    local flags: vector of string;
    if ( ssl?$ciphers )
        {
        for ( i in ssl$ciphers )
            ciphers_hex[i] = fmt("%x", ssl$ciphers[i]);
        }
    if ( ssl?$cextensions )
        {
        for ( i in ssl$cextensions )
            cextensions_hex[i] = fmt("%x", ssl$cextensions[i]);
        }
    if ( ssl?$compmethod && ssl$compmethod == 1 )
        flags[|flags|] = "compr";
    return cat_sep(":", "",
        ssl$version,
        join_string_vec(ciphers_hex, ","),
        join_string_vec(cextensions_hex, ","),
        join_string_vec(flags, ","));
    }

function finish(c: connection)
    {
    if ( ! (c?$ssl && c$ssl$version in set("DTLSv10", "DTLSv12")) )
        return;

    local l = Info($ts  = c$ssl$ts,
                   $uid = c$ssl$uid);
    if ( c$ssl?$numversion )
        l$version = c$ssl$numversion;
    if ( c$ssl?$ciphers )
        l$ciphers = c$ssl$ciphers;
    if ( c$ssl?$cextensions )
        l$cextensions = c$ssl$cextensions;
    if ( c$ssl?$ecurves )
        l$ecurves = c$ssl$ecurves;
    if ( c$ssl?$numcipher )
        l$cipher = c$ssl$numcipher;
    if ( c$ssl?$numcurve )
        l$curve = c$ssl$numcurve;
    if ( c$ssl?$compmethod)
        l$compmethod = c$ssl$compmethod;
    if ( c$ssl?$sextensions )
        l$sextensions = c$ssl$sextensions;
    l$cfingerprint = make_client_fingerprint(c$ssl);
    if ( c$ssl?$cert_chain && |c$ssl$cert_chain| > 0 && c$ssl$cert_chain[0]?$x509 )
        {
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
    c$ssl$ciphers = ciphers;
    }

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
    {
    c$ssl$numversion = version;
    c$ssl$numcipher = cipher;
    c$ssl$compmethod = comp_method;
    }

event ssl_extension(c: connection, is_orig: bool, code: count, val: string)
    {
    if ( is_orig )
        {
        if ( ! c$ssl?$cextensions )
            c$ssl$cextensions = index_vec();
        c$ssl$cextensions[|c$ssl$cextensions|] = code;
        }
    else
        {
        if ( ! c$ssl?$sextensions )
            c$ssl$sextensions = index_vec();
        c$ssl$sextensions[|c$ssl$sextensions|] = code;
        }
    }

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
    {
    c$ssl$ecurves = curves;
    }

event ssl_server_curve(c: connection, curve: count)
    {
    c$ssl$numcurve = curve;
    }

event ssl_established(c: connection)
    {
    finish(c);
    }

event ssl_alert(c: connection, is_orig: bool, level: count, desc: count)
    {
    finish(c);
    }
