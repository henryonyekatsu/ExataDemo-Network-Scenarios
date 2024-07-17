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

function attack7Success(src, dst, msg) {
    if (typeof attack7Success.countMap == 'undefined') {
        attack7Success.countMap = new Map();
    }
    if ([src, dst] in attack7Success.countMap) {
        var count = attack7Success.countMap[[src, dst]];
        count--;
        attack7Success.countMap[[src, dst]] = count;
    } else {
        attack7Success.countMap[[src, dst]] = 3;
    }
    if (attack7Success.countMap[[src, dst]] >= 0) {
        setTimeout(atfunc5, 100, src, dst, msg);
    }
};

const atfunc7 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'UserCred';
    attackInfo['src'] = src;
    attackInfo['dst'] = dst;
    parameters.push({
        'SIGNATURE': 'usercredsignature'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_USER_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_USER_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack7 = createAndLaunchAttack('UserCred', attackInfo, parameters);
    attack7.on('SUCCESS', (src, dst, msg) => attack7Success(src, dst, msg));
};

const atfunc6 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'NodeShutdown';
    attackInfo['src'] = src;
    attackInfo['dst'] = dst;
    parameters.push({
        'SIGNATURE': 'jshusyegshsyt'
    });
    parameters.push({
        'VULNERABILITY': 'NODE_SHUTDOWN'
    });
    parameters.push({
        'ACTION': 'SHUTDOWN_NODE'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack6 = createAndLaunchAttack('NodeShutdown', attackInfo, parameters);
};

function attack5Failure(src, dst, msg) {
    setTimeout(atfunc7, 100, src, dst, msg);
};

function attack5Success(src, dst, msg) {
    setTimeout(atfunc6, 100, src, dst, msg);
};

const atfunc5 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'RootCred';
    attackInfo['src'] = src;
    attackInfo['dst'] = dst;
    parameters.push({
        'SIGNATURE': 'rootcredentialsig'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_ROOT_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_ROOT_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack5 = createAndLaunchAttack('RootCred', attackInfo, parameters);
    attack5.on('SUCCESS', (src, dst, msg) => attack5Success(src, dst, msg));
    attack5.on('FAILURE', (src, dst, msg) => attack5Failure(src, dst, msg));
};

function attack4Success(src, dst, msg) {
    if (typeof attack4Success.countMap == 'undefined') {
        attack4Success.countMap = new Map();
    }
    if ([src, dst] in attack4Success.countMap) {
        var count = attack4Success.countMap[[src, dst]];
        count--;
        attack4Success.countMap[[src, dst]] = count;
    } else {
        attack4Success.countMap[[src, dst]] = 3;
    }
    if (attack4Success.countMap[[src, dst]] >= 0) {
        setTimeout(atfunc2, 100, src, dst, msg);
    }
};

const atfunc4 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'UserCred';
    attackInfo['src'] = src;
    attackInfo['dst'] = dst;
    parameters.push({
        'SIGNATURE': 'usercredsignature'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_USER_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_USER_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack4 = createAndLaunchAttack('UserCred', attackInfo, parameters);
    attack4.on('SUCCESS', (src, dst, msg) => attack4Success(src, dst, msg));
};

function attack3Action(src, dst, msg) {
    setTimeout(atfunc5, 100, src, dst, msg);
};

const atfunc3 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'NetScan';
    attackInfo['src'] = dst;
    parameters.push({
        'COMMAND': `NETSCAN ${dst} 1S 190.0.3.1 190.0.3.100 0S`
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack3 = createAndLaunchAttack('NetScan', attackInfo, parameters);
    attack3.on('ACTION', (src, dst, msg) => attack3Action(src, dst, msg));
};

function attack2Failure(src, dst, msg) {
    setTimeout(atfunc4, 100, src, dst, msg);
};

function attack2Success(src, dst, msg) {
    setTimeout(atfunc3, 100, src, dst, msg);
};

const atfunc2 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'RootCred';
    attackInfo['src'] = dst;
    attackInfo['dst'] = '190.0.2.6';
    parameters.push({
        'SIGNATURE': 'rootcredentialsig'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_ROOT_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_ROOT_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack2 = createAndLaunchAttack('RootCred', attackInfo, parameters);
    attack2.on('SUCCESS', (src, dst, msg) => attack2Success(src, dst, msg));
    attack2.on('FAILURE', (src, dst, msg) => attack2Failure(src, dst, msg));
};

function attack1Action(src, dst, msg) {
    setTimeout(atfunc2, 100, src, dst, msg);
};

const atfunc1 = () => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'PhishingEmailRootCred';
    attackInfo['src'] = '190.0.1.1';
    attackInfo['dst'] = '190.0.2.4';
    parameters.push({
        'SE-ATTACK-TYPE': 'MALEMAIL'
    });
    parameters.push({
        'PROP-VICTIM-SIDE': 'NO'
    });
    parameters.push({
        'PHISHING-EMAIL-TYPE': 'ATTACHMENT'
    });
    parameters.push({
        'PHISHING-EMAIL-ATTACHMENT-NAME': 'attachment.pdf'
    });
    parameters.push({
        'EMBEDDED-MALWARE-TYPE': 'VULNERABILITY-MALWARE'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_ROOT_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_ROOT_CREDENTIALS'
    });
    parameters.push({
        'SIGNATURE': 'aswshgsdertshsge'
    });
    let attack1 = createAndLaunchAttack('PhishingEmailRootCred', attackInfo, parameters);
    attack1.on('ACTION', (src, dst, msg) => attack1Action(src, dst, msg));
};

setTimeout(atfunc1, 0);