// Run with macOS JavaScript for Automation; no Python dependency on the target.
ObjC.import('Foundation');

function readSelections(path) {
    var text = $.NSString.stringWithContentsOfFileEncodingError(path, $.NSUTF8StringEncoding, null);
    var selections = JSON.parse(ObjC.unwrap(text)).selections;
    if (!selections || typeof selections !== 'object' || Array.isArray(selections) ||
        !Object.keys(selections).every(function (key) {
            return typeof selections[key] === 'string' &&
                key.indexOf('\0') === -1 && selections[key].indexOf('\0') === -1;
        })) {
        throw new Error('Invalid runtime selections');
    }
    return selections;
}

function quote(value) {
    return "'" + value.replace(/'/g, "'\\''") + "'";
}

function run(args) {
    var expected = readSelections(args[1]);
    var keys = Object.keys(expected).sort();
    if (args[0] === 'commands') {
        return 'set -e\n' + keys.map(function (key) {
            return [args[2], '--config', args[3], 'switch', '--', key, expected[key]]
                .map(quote).join(' ');
        }).join('\n');
    }
    if (args[0] !== 'verify') throw new Error('Unknown operation');
    var actual = readSelections(args[2]);
    if (JSON.stringify(keys) !== JSON.stringify(Object.keys(actual).sort()) ||
        !keys.every(function (key) { return expected[key] === actual[key]; })) {
        throw new Error('Runtime selections differ after restoration');
    }
}
