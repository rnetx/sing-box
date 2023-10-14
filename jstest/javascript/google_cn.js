
function Test(outbounds, now_selected) {
    var requests = new Array();

    for (var i = 0; i < outbounds.length; i++) {
        var outbound = outbounds[i];
        var request = {
            method: "GET",
            url: "https://www.youtube.com/premium",
            headers: {
                "Host": "www.youtube.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
                "Accept-Language": "en",
            },
            cookies: {
                "YSC": "BiCUU3-5Gdk",
                "CONSENT": "YES+cb.20220301-11-p0.en+FX+700",
                "GPS": "1",
                "VISITOR_INFO1_LIVE": "4VwPMkB7W5A",
                "PREF": "tz=Asia.Shanghai",
                "_gcl_au": "1.1.1809531354.1646633279",
            },
            detour: outbound
        };
        requests.push(request);
    }

    var results = http_requests(requests);

    if (typeof results == 'string') {
        return results;
    }

    log_debug("http requests success");

    var selected = null;
    var min_cost = 0;

    for (var i = 0; i < results.length; i++) {
        var result = results[i];
        if (result.error !== null && result.error !== "") {
            log_debug("detour: [" + outbounds[i] + "], status: [" + result.status + "], cost: [" + result.cost + "ms]")
            if (result.status === 200 && result.body !== "" && result.body.search("www.google.cn") < 0) {
                if (min_cost === 0 || result.cost < min_cost) {
                    selected = outbounds[i];
                    min_cost = result.cost;
                }
            }
        } else {
            log_error("detour: [" + outbounds[i] + "], error: [" + result.error + "]");
        }
    }

    if (selected == null) {
        return "No outbound is available";
    }

    return { selected: selected };
}
