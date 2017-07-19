'use strict';

module.exports = function parse(data) {
    var lines = data.split("\n");
    var headers = lines.shift();
    var indexOfMacAddress = headers.indexOf("BSSID");
    return lines.filter(filterBlanks).map(function(line){
        return parseLine(line, indexOfMacAddress);
    });
}

function cleanSecurity(security) {
    if(security.toLowerCase() === "none") {
        return "None";
    } else {
        return security.split("(")[0];
    }
}


function filterBlanks(line) {
    if (line.match(/\s*SSID\s*BSSID/gi)) {
        return false;
    }
    else if (line.match(/\s*\d*\s*IBSS network/gi)) {
        return false;
    }
    return line.replace(/\s+/g,"").length !== 0;
}

function parseLine(line, indexOfMacAddress) {
    var ssid = line.substr(0, indexOfMacAddress).trim();
    line = line.substr(indexOfMacAddress, line.length - indexOfMacAddress);

    var components = line.replace(/\s{1,}/g, " ").trim().split(" ");
    //[0] SSID
    //[1] MAC
    //[2] RSSI
    //[3] CHANNEL
    //[4] HT
    //[5] CC
    //[6..x] SECURITY (auth/unicast/group)

    var channel = components[2] ? components[2].split(',')[0] : -1 ;

    return {
        ssid,
        mac: components[0].toLowerCase(),
        channel: channel,
        security: components.splice(5).map(cleanSecurity).sort()
    };
}
