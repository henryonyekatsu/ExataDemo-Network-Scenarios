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

const atfunc5 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'DataTransfer';
    attackInfo['src'] = src;
    attackInfo['dst'] = dst;
    parameters.push({
        'SIGNATURE': 'rgergserg'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_DATA_TRANSFER'
    });
    parameters.push({
        'ACTION': 'START_DATA_TRANSFER'
    });
    parameters.push({
        'HOST_MODEL_DATA_TRANSFER': `190.0.6.1 DURATION DET 100S DELIVERY-TYPE RELIABLE CONNECTION-RETRY 0 DET 1S REQUEST-NUM DET 1000 REQUEST-SIZE DET 512 REQUEST-INTERVAL DET 1S REQUEST-TOS PRECEDENCE 0`
    });
    parameters.push({
        'HOST_MODEL_DATA_TRANSFER_ORIGINAL_ATTACKER': `${src}`
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack5 = createAndLaunchAttack('DataTransfer', attackInfo, parameters);
};

function attack4Success(src, dst, msg) {
    setTimeout(atfunc5, 100, src, dst, msg);
};

const atfunc4 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'User_credentials';
    attackInfo['src'] = dst;
    attackInfo['dst'] = '190.0.5.1';
    parameters.push({
        'SIGNATURE': 'signedusercred'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_USER_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_USER_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack4 = createAndLaunchAttack('User_credentials', attackInfo, parameters);
    attack4.on('SUCCESS', (src, dst, msg) => attack4Success(src, dst, msg));
};

function attack3Action(src, dst, msg) {
    setTimeout(atfunc4, 100, src, dst, msg);
};

const atfunc3 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'NetScan';
    attackInfo['src'] = '190.0.1.1';
    parameters.push({
        'COMMAND': `NETSCAN 190.0.1.1 1S 190.0.5.1 190.0.5.100 0S`
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack3 = createAndLaunchAttack('NetScan', attackInfo, parameters);
    attack3.on('ACTION', (src, dst, msg) => attack3Action(src, dst, msg));
};

function attack2Success(src, dst, msg) {
    setTimeout(atfunc3, 100, src, dst, msg);
};

const atfunc2 = (src, dst, msg) => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'User_credentials';
    attackInfo['src'] = dst;
    attackInfo['dst'] = '190.0.5.7';
    parameters.push({
        'SIGNATURE': 'signedusercred'
    });
    parameters.push({
        'VULNERABILITY': 'VUL_USER_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_USER_CREDENTIALS'
    });
    let extraParams = extractExtraParams(msg);
    parameters = parameters.concat(extraParams);
    let attack2 = createAndLaunchAttack('User_credentials', attackInfo, parameters);
    attack2.on('SUCCESS', (src, dst, msg) => attack2Success(src, dst, msg));
};

function attack1Action(src, dst, msg) {
    setTimeout(atfunc2, 100, src, dst, msg);
};

const atfunc1 = () => {
    let attackInfo = {};
    let parameters = [];
    attackInfo['attackName'] = 'Phishingmail1';
    attackInfo['src'] = '190.0.6.1';
    attackInfo['dst'] = '190.0.3.2';
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
        'VULNERABILITY': 'VUL_USER_CREDENTIALS'
    });
    parameters.push({
        'ACTION': 'STEAL_USER_CREDENTIALS'
    });
    parameters.push({
        'SIGNATURE': 'Phishingsign1'
    });
    let attack1 = createAndLaunchAttack('Phishingmail1', attackInfo, parameters);
    attack1.on('ACTION', (src, dst, msg) => attack1Action(src, dst, msg));
};

setTimeout(atfunc1, 0);