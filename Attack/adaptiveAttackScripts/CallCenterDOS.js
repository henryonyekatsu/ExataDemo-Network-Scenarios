const createAndLaunchAttack = (templateName, attackInfo, parameters) => {
    let attack;
    attack = attackFactory.createAttack(templateName, function(attackOb) {
        attackOb.srcAddr = attackInfo['src'];
        attackOb.dstAddr = attackInfo['dst'];
        attackOb.attackName = attackInfo['attackName'];
        for (let parameter in parameters) {
            let pair = parameters[parameter];
            let key = Object.keys(pair);
            attackOb.addParam(key, pair[key]);
        }
        attackOb.Launch();
    });
    return attack;
};

const jsonToArray = (obj) => {
    let result = [];
    for (let key in obj) {
        result.push({
            [key]: obj[key]
        });
    };
    return result;
};

const extractExtraParams = (msg) => {
    let extraParams = [];
    if (!msg) return extraParams;
    try {
        msgJson = JSON.parse(msg);
        extraParams = jsonToArray(msgJson);
    } catch (e) {
        return extraParams;
    }
    return extraParams;
};

const atfunc2 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'DosAttack';
    attackInfo['src'] = dst;
    parameters.push({
        'COMMAND': `DOS ${dst} 3 1 2 3 BASIC 1025 RATE 10000 10.9M RAMP-UP-TIME 0S`
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack2 = createAndLaunchAttack('DosAttack', attackInfo, parameters);
};

function attack1Action(src, dst, msg) {
    setTimeout(atfunc2, 100, src, dst, msg);
};

const atfunc1 = () => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'NetScan';
    attackInfo['src'] = '190.0.1.1';
    parameters.push({
        'COMMAND': `NETSCAN 190.0.1.1 1S 190.0.4.1 190.0.4.100 0S`
    });
    let attack1 = createAndLaunchAttack('NetScan', attackInfo, parameters);
    attack1.on('ACTION', (src, dst, msg) => attack1Action(src, dst, msg));
};

setTimeout(atfunc1, 0);