// Use of this source code is governed by the Blue Oak Model License
// 1.0.0; see LICENSE.

class Encoder extends Array {
    u8(val) {
        this.push(val);
    }
    u32le(val) {
        this.push((val >>>  0) & 0xff, (val >>>  8) & 0xff,
                  (val >>> 16) & 0xff, (val >>> 24) & 0xff);
    }
    sleb(val) {
        for (;;) {
            let u8 = (val + 64n) & 0x7fn;
            if (u8 == head) {
                this.u8(Number(u8));
                return;
            }
            this.u8(Number(0x80n | u8));
            val >>= 7n;
        }
    }
    uleb(val) {
        for (;;) {
            let next = val >> 7n;
            if (next == 0n) {
                this.u8(Number(val));
                return;
            }
            this.u8(Number(0x80n | (val & 0x7fn)));
            val = next;
        }
    }
    f32(val) {
        throw new Error("unimplemented");
    }
    f64(val) {
        throw new Error("unimplemented");
    }
    bytes(val) {
        for (let u8 of val) { this.u8(u8); }
    }
    utf8(codepoint) {
        if (codepoint <= 0x7f) {
            this.u8(codepoint);
        } else {
            let count, offset;
            if (0x80 <= codepoint && codepoint <= 0x07FF) {
                count = 1;
                offset = 0xC0;
            } else if (0x0800 <= codepoint && codepoint <= 0xFFFF) {
                count = 2;
                offset = 0xE0;
            } else if (0x10000 <= codepoint && codepoint <= 0x10FFFF) {
                count = 3;
                offset = 0xF0;
            } else {
                throw new Error(`Bad codepoint: ${codepoint}`);
            }
            this.u8((codepoint >> (6 * count)) + offset);
            for (; count; count--) {
                var unit = codepoint >> (6 * (count - 1));
                this.u8(0x80 | (unit & 0x3F));
            }
        }
    }
    finish() { return new Uint8Array(this); }
}

// This parser for the text format of WebAssembly is intended to accept
// all valid productions of the textual grammar, but it is not a
// validating parser; it could fail to signal an error for some invalid
// productions.
function read(str) {
    let pos = 0;
    function line() {
        let ret = 1;
        for (let i = 0; i < pos; i++) {
            if (str.charAt(i) == '\n') { ret++; }
        }
        return ret;
    }
    function col() {
        let ret = 0;
        for (let i = 0; i < pos; i++) {
            ret = str.charAt(i) == '\n' ? 0 : ret + 1;
        }
        return ret;
    }
    function error(msg) {
        throw new Error(`<input>:${line()}:${col()}: ${msg}`);
    }
    function assert(x, msg) {
        if (!x) { error(msg); }
        return x;
    }
    function eof() { return pos == str.length; }
    function peek() {
        assert(!eof(), "unexpected end of string");
        return str.charAt(pos);
    }
    function drop(n = 1) {
        assert(pos + n <= str.length, "unexpected end of string");
        pos += n;
    }
    function next() {
        let ch = peek();
        drop();
        return ch;
    }
    function dropWhile(pattern) {
        while (!eof() && peek().match(pattern)) {
            drop();
        }
    }
    function peekMatch(pattern) {
        let re = new RegExp(pattern, 'y');
        re.lastIndex = pos;
        let res = re.exec(str);
        if (!res) { return false; }
        return res[0];
    }
    function match(pattern) {
        let res = peekMatch(pattern);
        if (res) { drop(res.length); }
        return res;
    }
    function consume(pattern, msg = 'unexpected token') {
        return assert(match(pattern), msg);
    }
    function skipWhitespace() {
        while (!eof()) {
            if (match('\\s+')) {
                continue;
            } else if (match('\\(;')) {
                skipBlockComment();
            } else if (match(';;')) {
                skipLineComment();
            } else {
                break;
            }
        }
    }
    function skipBlockComment() {
        while (1) {
            let ch = next();
            if (ch == ';') {
                if (match('\\)')) {
                    return;
                }
            } else if (ch == '(') {
                if (match(';')) {
                    skipBlockComment();
                }
            }
        }
    }
    function skipLineComment() {
        while (!eof()) {
            if (next() == '\n') {
                return;
            }
        }
    }
    function terminal(x) {
        assert(eof() || peekMatch('(\\s|;;|\\(;|;\\)|\\(|\\))'),
               "unexpected characters");
        return x;
    }
    function readDecimalInteger(sign) {
        let q = match('[0-9_]+').replace('_', '');
        assert(q != '', "expected an integer");
        return BigInt(sign + q);
    }
    function readDecimal(sign) {
        let q = readDecimalInteger(sign);
        let f;
        if (match('\\.')) {
            f = readDecimalInteger('+');
        }
        if (match('[Ee]')) {
            let mantissa = q.toString();
            if (f) {
                mantissa += '.' + f.toString();
            }
            let e = match('[+-]') || '+';
            return Number(mantissa + 'e' + readDecimalInteger(e).toString());
        }
        if (f) {
            return Number(q.toString() + '.' + f.toString());
        }
        return q;
    }
    function readHexadecimalInteger(sign) {
        let q = match('[0-9abcdefABCDEF_]+').replace('_', '');
        assert(q != '', "expected an integer")
        return BigInt('0x' + q) * (sign == '+' ? 1n : -1n);
    }
    function readHexadecimal(sign) {
        let q = readHexadecimalInteger(sign);
        assert(!match('\\.'), "hex floats not supported")
        assert(!match('[pP]'), "hex floats not supported")
        return q;
    }
    function readNumber(sign = '+') {
        return match('0x') ? readHexadecimal(sign) : readDecimal(sign);
    }
    function readString() {
        consume('"');
        let enc = new Encoder;
        for (let ch = next(); ch != '"'; ch = next()) {
            if (ch == '/') {
                switch (ch = next()) {
                case 't':
                    enc.utf8('\t'.charCodeAt(0));
                    break;
                case 'n':
                    enc.utf8('\n'.charCodeAt(0));
                    break;
                case 'r':
                    enc.utf8('\r'.charCodeAt(0));
                    break;
                case "'":
                case '\\':
                    enc.utf8(ch.charCodeAt(0));
                    break;
                case 'u': {
                    consume('{', "bad unicode escape");
                    let code = readHexadecimalInteger('+');
                    consume('}', "bad unicode escape");
                    assert(code < 0xd800n || (0xE000n <= code && code < 0x110000n),
                           "bad escaped codepoint");
                    enc.utf8(code);
                }
                default:
                    error("bad escape in string");
                }
            } else {
                let code = ch.charCodeAt(0);
                assert(code >= 0x20 && code != 0x7f, "bad char");
                enc.utf8(code);
            }
        }
        return enc.finish();
    }
    function readIdentifier() {
        consume('\\$');
        return '$' + readKeyword();
    }
    function readSequence() {
        let ret = [];
        consume('\\(');
        for (skipWhitespace(); !match('\\)'); skipWhitespace()) {
            ret.push(read1(str));
        }
        return ret;
    }
    function readKeyword() {
        return consume('[0-9A-Za-z!#$%&\'*+./:<=>?@\\\\^_`|~-]+');
    }

    function read1() {
        skipWhitespace();
        switch (peek()) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            return terminal(readNumber());
        case '+':
        case '-':
            return terminal(readNumber(next()));
        case '"':
            return terminal(readString());
        case '$':
            return terminal(readIdentifier());
        case '(':
            return readSequence();
        default:
            return terminal(readKeyword());
        }
    }

    let ret = read1();
    skipWhitespace();
    assert(eof(), "expected just one top-level form");
    return ret;
}

const opcodes = {
    'unreachable': 0x00, 'nop': 0x01,
    'block': 0x02, 'loop': 0x03, 'if': 0X04, 'else': 0x05, 'end': 0x0B,
    'br': 0x0C, 'br_if': 0x0D, 'br_table': 0x0E,
    'return': 0X0F,
    'call': 0x10, 'call_indirect': 0x11,
    'drop': 0x1A, 'select': 0x1B,
    'local.get': 0x20, 'local.set': 0x21, 'local.tee': 0x22,
    'global.get': 0x23, 'global.set': 0x24,
    'i32.load': 0x28, 'i64.load': 0x29, 'f32.load': 0x2A, 'f64.load': 0x2B,
    'i32.load8_s': 0x2C, 'i32.load8_u': 0x2D,
    'i32.load16_s': 0x2E, 'i32.load16_u': 0x2F,
    'i64.load8_s': 0x30, 'i64.load8_u': 0x31,
    'i64.load16_s': 0x32, 'i64.load16_u': 0x33,
    'i64.load32_s': 0x34, 'i64.load32_u': 0x35,
    'i32.store': 0x36, 'i64.store': 0x37,
    'f32.store': 0x38, 'f64.store': 0x39,
    'i32.store8': 0x3A, 'i32.store16': 0x3B,
    'i64.store8': 0x3C, 'i64.store16': 0x3D, 'i64.store32': 0x3E,
    'memory.size': 0x3F, 'memory.grow': 0x40,
    'i32.const': 0x41, 'i64.const': 0x42,
    'f32.const': 0x43, 'f64.const': 0x44,
    'i32.eqz': 0x45, 'i32.eq': 0x46, 'i32.ne': 0x47,
    'i32.lt_s': 0x48, 'i32.lt_u': 0x49, 'i32.gt_s': 0x4A, 'i32.gt_u': 0x4B,
    'i32.le_s': 0x4C, 'i32.le_u': 0x4D, 'i32.ge_s': 0x4E, 'i32.ge_u': 0x4F,
    'i64.eqz': 0x50, 'i64.eq': 0x51, 'i64.ne': 0x52,
    'i64.lt_s': 0x53, 'i64.lt_u': 0x54, 'i64.gt_s': 0x55, 'i64.gt_u': 0x56,
    'i64.le_s': 0x57, 'i64.le_u': 0x58, 'i64.ge_s': 0x59, 'i64.ge_u': 0x5A,
    'f32.eq': 0x5B, 'f32.ne': 0x5C,
    'f32.lt': 0x5D, 'f32.gt': 0x5E, 'f32.le': 0x5F, 'f32.ge': 0x60,
    'f64.eq': 0x61, 'f64.ne': 0x62,
    'f64.lt': 0x63, 'f64.gt': 0x64, 'f64.le': 0x65, 'f64.ge': 0x66,
    'i32.clz': 0x67, 'i32.ctz': 0x68, 'i32.popcnt': 0x69,
    'i32.add': 0x6A, 'i32.sub': 0x6B, 'i32.mul': 0x6C,
    'i32.div_s': 0x6D, 'i32.div_u': 0x6E,
    'i32.rem_s': 0x6F, 'i32.rem_u': 0x70,
    'i32.and': 0x71, 'i32.or': 0x72, 'i32.xor': 0x73,
    'i32.shl': 0x74, 'i32.shr_s': 0x75, 'i32.shr_u': 0x76,
    'i32.rotl': 0x77, 'i32.rotr': 0x78,
    'i64.clz': 0x79, 'i64.ctz': 0x7A, 'i64.popcnt': 0x7B,
    'i64.add': 0x7C, 'i64.sub': 0x7D, 'i64.mul': 0x7E,
    'i64.div_s': 0x7F, 'i64.div_u': 0x80,
    'i64.rem_s': 0x81, 'i64.rem_u': 0x82,
    'i64.and': 0x83, 'i64.or': 0x84, 'i64.xor': 0x85,
    'i64.shl': 0x86, 'i64.shr_s': 0x87, 'i64.shr_u': 0x88,
    'i64.rotl': 0x89, 'i64.rotr': 0x8A,
    'f32.abs': 0x8B, 'f32.neg': 0x8C,
    'f32.ceil': 0x8D, 'f32.floor': 0x8E, 'f32.trunc': 0x8F,
    'f32.nearest': 0x90,
    'f32.sqrt': 0x91,
    'f32.add': 0x92, 'f32.sub': 0x93, 'f32.mul': 0x94, 'f32.div': 0x95,
    'f32.min': 0x96, 'f32.max': 0x97, 'f32.copysign': 0x98,
    'f64.abs': 0x99, 'f64.neg': 0x9A,
    'f64.ceil': 0x9B, 'f64.floor': 0x9C, 'f64.trunc': 0x9D,
    'f64.nearest': 0x9E,
    'f64.sqrt': 0x9F,
    'f64.add': 0xA0, 'f64.sub': 0xA1, 'f64.mul': 0xA2, 'f64.div': 0xA3,
    'f64.min': 0xA4, 'f64.max': 0xA5, 'f64.copysign': 0xA6,
    'i32.wrap_i64': 0xA7,
    'i32.trunc_f32_s': 0xA8, 'i32.trunc_f32_u': 0xA9,
    'i32.trunc_f64_s': 0xAA, 'i32.trunc_f64_u': 0xAB,
    'i64.extend_i32_s': 0xAC, 'i64.extend_i32_u': 0xAD,
    'i64.trunc_f32_s': 0xAE, 'i64.trunc_f32_u': 0xAF,
    'i64.trunc_f64_s': 0xB0, 'i64.trunc_f64_u': 0xB1,
    'f32.convert_i32_s': 0xB2, 'f32.convert_i32_u': 0xB3,
    'f32.convert_i64_s': 0xB4, 'f32.convert_i64_u': 0xB5,
    'f32.demote_f64': 0xB6,
    'f64.convert_i32_s': 0xB7, 'f64.convert_i32_u': 0xB8,
    'f64.convert_i64_s': 0xB9, 'f64.convert_i64_u': 0xBA,
    'f64.promote_f32': 0xBB,
    'i32.reinterpret_f32': 0xBC, 'i64.reinterpret_f64': 0xBD,
    'f32.reinterpret_i32': 0xBE, 'f64.reinterpret_i64': 0xBF,
};

function parse(expr) {
    let isSeq = x => x instanceof Array;
    let isId  = x => typeof x == 'string' && x.startsWith('$');
    let isKw  = x => typeof x == 'string' && !isId(x);
    let isStr = x => x instanceof Uint8Array;
    let isU32 = x => typeof x == 'bigint' && 0n <= x && x < (1n << 32n);
    let isS32 = x => typeof x == 'bigint' && (-1n << 31n) <= x && x < (1n << 31n);
    let isU64 = x => typeof x == 'bigint' && 0n <= x && x < (1n << 64n);
    let isS64 = x => typeof x == 'bigint' && (-1n << 63n) <= x && x < (1n << 63n);

    function error(msg) { throw new Error(msg); }
    function assert(x, msg) {
        if (!x) { error(msg); }
        return x;
    }
    function empty(x) { return x.length === 0; }
    function isTagged(x) {
        return isSeq(x) && !empty(x) && isKw(x[0]);
    }
    function matchTagged(x, kw) {
        if (isTagged(x) && x[0] === kw) {
            x.shift();
            return true;
        }
        return false;
    }
    function popTag(x) {
        assert(isTagged(x), "expected tagged sequence");
        return x.shift();
    }
    function popId(x) { if (isId(x[0])) { return x.shift(); } }

    // Identifiers with a space can't be in the source program.
    let freshIdx = 0;
    function freshId() { return `$fresh ${freshIdx++}`; }

    assert(matchTagged(expr, 'module'), "expected module form");
    let id = popId(expr);
    let accum = { type: [], import: [], func: [], table: [], memory: [],
                  global: [], export: [], start: [], elem: [], data: [] };

    for (let field of expr) {
        let tag = popTag(field);
        assert(accum[tag] !== undefined, "unexpected tag: ${tag}");
        accum[tag].push(field);
    }

    function parseValType(x) {
        assert(x === 'i32' || x === 'i64' || x === 'f32' || x === 'f64',
               `bad valtype: ${x}`);
        return x;
    }
    function parseParams(x) {
        let id = popId(x);
        if (id) { assert(x.length == 1); }
        return x.map(t => ({ id, type: parseValType(t) }));
    }
    function parseResults(x) {
        return x.map(parseValType);
    }
    function parseFuncSig(x) {
        let params = [], results = [];
        while (!empty(x)) {
            if (!matchTagged(x[0], 'param')) { break; }
            for (let p of parseParams(x.shift())) { params.push(p); }
        }
        while (!empty(x)) {
            if (!matchTagged(x[0], 'result')) { break; }
            for (let r of parseResults(x.shift())) { results.push(r); }
        }
        return { params, results };
    }
    function parseFuncType(x) {
        assert(matchTagged(x, 'func'), "expected func type");
        let { params, results } = parseFuncSig(x);
        assert(empty(x), "expected params then results");
        return { params, results };
    }
    function parseTypeUse(x) {
        let idx;
        if (!empty(x) && matchTagged(x[0], 'type')) {
            assert(x[0].length == 1, "bad type use");
            idx = x.shift()[0];
        }
        let { params, results } = parseFuncSig(x);
        return { idx, params, results };
    }
    function parseBlockType(x) {
        return parseTypeUse(x);
    }
    function parseLimits(x) {
        let min = x.shift();
        assert(isU32(min), "bad min");
        let max;
        if (isU32(x[0])) { max = x.shift(); }
        return { min, max };
    }
    function parseElemType(x) {
        let elemtype = x.shift();
        assert(elemtype === 'funcref', "bad elem type");
        return elemtype;
    }        
    function parseTableType(x) {
        let limits = parseLimits(x);
        assert(x.length === 1, "bad table type");
        let elemtype = parseElemType(x);
        return { limits, elemtype };
    }
    function parseMemType(x) {
        let limits = parseLimits(x);
        assert(empty(x), "bad mem type");
        return { limits };
    }
    function parseGlobalType(x) {
        assert(x.length === 1, "bad global type");
        let mut = false;
        let t = x[0];
        if (isSeq(t)) {
            assert(matchTagged(t, 'mut') && t.length === 1, "expected mut");
            t = t[0];
        }
        let type = parseValType(t);
        return { mut, type };
    }
    function hasIdx(x) {
        return !empty(x) && (isU32(x[0]) || isId(x[0]));
    }
    function parseIdx(x) {
        assert(hasIdx(x), "expected an index");
        return x.shift();
    }

    function parseType(x) {
        let id = popId(x);
        assert(x.length == 1, "bad type");
        return { id, kind:'functype', val:parseFuncType(x[0]) };
    }
    function parseImport(x) {
        assert(x.length == 3, "bad import");
        let [mod, name, desc] = x;
        assert(isStr(mod) && isStr(name) && isTagged(desc), "bad import");
        let kind = desc.shift();
        let id = popId(desc);
        let val;
        if (kind === 'func') {
            val = parseTypeUse(desc);
            assert(empty(desc), "bad func import");
        } else if (kind === 'table') {
            val = parseTableType(desc);
        } else if (kind === 'mem') {
            val = parseMemType(desc);
        } else if (kind === 'global') {
            val = parseGlobalType(desc);
        } else {
            error("bad import descriptor");
        }
        return { mod, name, kind, id, val };
    }
    function parseExport(x) {
        assert(x.length == 2, "bad export");
        let [name, desc] = x;
        assert(isStr(name) && isTagged(desc) && desc.length == 2, "bad export");
        let [kind, idx] = desc;
        assert(kind == 'func' || kind == 'table' || kind == 'mem' ||
               kind == 'global', "bad export");
        return { name, kind, idx };
    }
    function parseMemArg(x) {
        let offset = 0n, align = 0n;
        if (!empty(x) && isKw(x[0]) && x[0].startsWith('offset=')) {
            offset = BigInt(x.shift().substring(('offset=').length));
        }
        if (!empty(x) && isKw(x[0]) && x[0].startsWith('align=')) {
            align = BigInt(x.shift().substring(('align=').length));
        }
        return { offset, align };
    }
    function unfoldInstruction(inst, input) {
        let tag = popTag(inst);
        switch (tag) {
        case 'block':
        case 'loop':
            input.unshift('end');
            while (!empty(inst)) { input.unshift(inst.pop()); }
            input.unshift(tag);
            break;
        case 'if': {
            let label = popId(inst);
            let type = parseBlockType(inst);
            let folded = [];
            while (!empty(inst) && !(isTagged(inst[0]) && inst[0][0] === 'then')) {
                folded.push(inst.shift());
            }
            assert(!empty(inst) && matchTagged(inst[0], 'then'), "bad folded if");
            let thenInsts = inst.shift();
            let elseInsts = [];
            if (!empty(inst)) {
                assert(matchTagged(inst[0], 'else'), "bad folded if");
                elseInsts = inst.shift();
            }
            assert(empty(inst), "bad folded if");
            input.unshift('end');
            while (!empty(elseInsts)) { input.unshift(elseInsts.pop()); }
            input.unshift('else');
            while (!empty(thenInsts)) { input.unshift(thenInsts.pop()); }
            if (blockType.idx) {
                input.unshift(['type', blockType.idx]);
            } else {
                input.unshift(['param', ...type.params],
                              ['result', ...type.results]);
            }
            if (label) { input.unshift(label); }
            input.unshift('if');
            break;
        }
        case 'br':
        case 'br_if':
        case 'call':
        case 'local.get':
        case 'local.set':
        case 'local.tee':
        case 'global.get':
        case 'global.tee':
            input.unshift(tag, parseIdx(inst));
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        case 'br_table': {
            let targets = [];
            while (hasIdx(inst)) { targets.push(inst.shift()); }
            input.unshift(tag, ...targets);
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        }
        case 'call_indirect': {
            let type = parseTypeUse(inst);
            if (type.idx !== undefined) {
                input.unshift(tag, ['type', type.idx]);
            } else {
                input.unshift(tag, ['param', ...type.params],
                              ['result', ...type.results]);
            }
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        }
        case 'i32.load':
        case 'i64.load':
        case 'f32.load':
        case 'f64.load':
        case 'i32.load8_s':
        case 'i32.load8_u':
        case 'i32.load16_s':
        case 'i32.load16_u':
        case 'i64.load8_s':
        case 'i64.load8_u':
        case 'i64.load16_s':
        case 'i64.load16_u':
        case 'i64.load32_s':
        case 'i64.load32_u':
        case 'i32.store':
        case 'i64.store':
        case 'f32.store':
        case 'f64.store':
        case 'i32.store8':
        case 'i32.store16':
        case 'i64.store8':
        case 'i64.store16':
        case 'i64.store32': {
            let arg = parseMemArg(inst);
            if (arg.align) {
                input.unshift(`align=${arg.align}`);
            }
            if (arg.offset) {
                input.unshift(`offset=${arg.offset}`);
            }
            input.unshift(tag);
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        }
        case 'i32.const':
        case 'i64.const':
        case 'f32.const':
        case 'f64.const':
            input.unshift(tag, inst.shift());
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        default:
            assert(tag in opcodes, `bad instruction: ${tag}`);
            input.unshift(tag);
            while (!empty(inst)) { input.unshift(inst.pop()); }
            break;
        }
    }
    function parseInstructions(x, blockKind) {
        function skipEndLabel(orig) {
            let label = popId(x);
            assert(label === undefined || label === orig,
                   `bad end label: ${label}`);
        }
        let out = [];
        while (1) {
            if (empty(x)) {
                assert(blockKind == 'body',
                       "unexpected end of instruction sequence");
                return out;
            }
            let inst = x.shift();
            if (isSeq(inst)) {
                unfoldInstruction(inst, x);
                continue;
            }
            assert(isKw(inst), `bad instruction: ${inst}`);
            switch (inst) {
            case 'block':
            case 'loop': {
                let label = popId(x);
                let type = parseBlockType(x);
                out.push([inst, label, type, parseInstructions(x, inst)]);
                skipEndLabel(label);
                break;
            }
            case 'if': {
                let label = popId(x);
                let type = parseBlockType(x);
                let thenInsts = parseInstructions(x, 'then');
                let how = thenInsts.pop();
                skipEndLabel(label);
                let elseInsts = [];
                if (how == 'else') {
                    elseInsts = parseInstructions(x, 'else');
                    skipEndLabel(label);
                }
                out.push(['if', label, type, thenInsts, elseInsts]);
                break;
            }
            case 'else':
                assert(blockKind === 'then');
                // Fall through.
            case 'end':
                if (blockKind === 'then') { out.push(inst); }
                assert(blockKind !== 'body');
                return out;
            case 'br':
            case 'br_if':
            case 'call':
            case 'local.get':
            case 'local.set':
            case 'local.tee':
            case 'global.get':
            case 'global.tee':
                out.push([inst, parseIdx(x)]);
                break;
            case 'br_table': {
                out.push([inst]);
                let targets = [];
                assert(hasIdx(x), "no targets for br_table");
                while (hasIdx(x)) { targets.push(x.shift()); }
                out.push([inst, targets, targets.pop()]);
                break;
            }
            case 'call_indirect':
                out.push([inst, parseTypeUse(x)]);
                break;
            case 'i32.load':
            case 'i64.load':
            case 'f32.load':
            case 'f64.load':
            case 'i32.load8_s':
            case 'i32.load8_u':
            case 'i32.load16_s':
            case 'i32.load16_u':
            case 'i64.load8_s':
            case 'i64.load8_u':
            case 'i64.load16_s':
            case 'i64.load16_u':
            case 'i64.load32_s':
            case 'i64.load32_u':
            case 'i32.store':
            case 'i64.store':
            case 'f32.store':
            case 'f64.store':
            case 'i32.store8':
            case 'i32.store16':
            case 'i64.store8':
            case 'i64.store16':
            case 'i64.store32':
                out.push([inst, parseMemArg(x)]);
                break;
            case 'i32.const':
                assert(!empty(x) && isS32(x[0]),
                       `expected an s32: ${x[0]}`)
                out.push([inst, x.shift()]);
                break;
            case 'i64.const':
                assert(!empty(x) && isS64(x[0]),
                       `expected an s64: ${x[0]}`)
                out.push([inst, x.shift()]);
                break;
            case 'f32.const':
            case 'f64.const':
                assert(!empty(x) && typeof x[0] == 'number',
                       `expected a number: ${x[0]}`)
                out.push([inst, x.shift()]);
                break;
            default:
                out.push([inst]);
                break;
            }
        }
    }
    function parseOffset(x) {
        return parseInstructions(matchTagged(x, 'offset') ? x : [x], 'body');
    }
    function parseElem(x) {
        let idx = hasIdx(x) ? x.shift() : 0n;
        let offset = parseOffset(x.shift());
        return {idx, offset, init: x};
    }
    function concatUint8Arrays(arrays) {
        let len = 0;
        for (let x of arrays) { len += x.length; }
        let ret = new Uint8Array(len);
        let offset = 0;
        for (let x of arrays) {
            x.copyWithin(ret, offset);
            offset += x.length;
        }
        return ret;
    }
    function parseData(x) {
        let idx = hasIdx(x) ? x.shift() : 0n;
        let offset = parseOffset(x.shift());
        let init = concatUint8Arrays(x);
        return { idx, offset, init };
    }
    function visitFunc(x) {
        let id = popId(x);
        while (!empty(x) && matchTagged(x[0], 'export')) {
            let export_ = x.shift();
            assert(export_.length == 1, "bad export")
            let [name] = export_;
            if (id === undefined) { id = freshId(); }
            exports.push({ name, kind: 'func', idx: id });
        }
            
        if (!empty(x) && matchTagged(x[0], 'import')) {
            let names = x.shift();
            assert(names.length == 2, "bad import")
            let [mod, name] = names;
            assert(isStr(mod) && isStr(name), "bad import");
            let type = parseTypeUse(x);
            assert(empty(x), "bad import")
            imports.push({mod, name, kind: 'func', id, val: type});
            return;
        }

        let type = parseTypeUse(x);
        let locals = [];
        while (!empty(x) && matchTagged(x[0], 'local')) {
            let local = x.shift();
            let id = popId(local);
            if (id) { assert(local.length == 1, "bad local") }
            for (let t of local) {
                locals.push({id, type: parseValType(t)});
            }
        }
        let body = parseInstructions(x, 'body');
        funcs.push({id, type, locals, body})
    }
    function visitTable(x) {
        let id = popId(x);
        while (!empty(x) && matchTagged(x[0], 'export')) {
            let export_ = x.shift();
            assert(export_.length == 1, "bad export")
            let [name] = export_;
            if (id === undefined) { id = freshId(); }
            exports.push({ name, kind: 'table', idx: id });
        }
            
        if (!empty(x) && matchTagged(x[0], 'import')) {
            let names = x.shift();
            assert(names.length == 2, "bad import")
            let [mod, name] = names;
            assert(isStr(mod) && isStr(name), "bad import");
            let type = parseTableType(x);
            assert(empty(x), "bad import")
            imports.push({mod, name, kind: 'table', id, val: type});
            return;
        }

        assert(!empty(x), "bad table declaration");
        if (matchTagged(x[x.length-1], 'elem')) {
            let segment = x.pop();
            let elemtype = parseElemType(x);
            assert(empty(x), "bad inline element segment");
            if (id === undefined) { id = freshId(); }
            elems.push({table:id, offset:[['i32.const', 0n]], init: segment});
            let len = BigInt(segment.length)
            tables.push({id, type:{limits: {min:len, max:len}, elemtype}});
        } else {
            tables.push({id, type:parseTableType(x)});
            assert(empty(x), "bad table declaration");
        }
    }
    function visitMem(x) {
        let id = popId(x);

        while (!empty(x) && matchTagged(x[0], 'export')) {
            let export_ = x.shift();
            assert(export_.length == 1, "bad export")
            let [name] = export_;
            if (id === undefined) { id = freshId(); }
            exports.push({ name, kind: 'mem', idx: id });
        }
            
        if (!empty(x) && matchTagged(x[0], 'import')) {
            let names = x.shift();
            assert(names.length == 2, "bad import")
            let [mod, name] = names;
            assert(isStr(mod) && isStr(name), "bad import");
            let type = parseMemType(x);
            assert(empty(x), "bad import")
            imports.push({mod, name, kind: 'mem', id, val: type});
            return;
        }

        if (!empty(x) && matchTagged(x[0], 'data')) {
            let init = concatUint8Arrays(x);
            if (id === undefined) { id = freshId(); }
            datas.push({idx: id, offset: [['i32.const', 0n]], init});
            assert(empty(x), "bad inline data segment");
            let type = { min: BigInt(init.length), max: BigInt(init.length) };
            mems.push({id, type});
            return;
        }

        let type = parseMemType(x);
        assert(empty(x), "bad mem declaration")
        mems.push({id, type});
    }
    function visitGlobal(x) {
        let id = popId(x);

        while (!empty(x) && matchTagged(x[0], 'export')) {
            let export_ = x.shift();
            assert(export_.length == 1, "bad export")
            let [name] = export_;
            if (id === undefined) { id = freshId(); }
            exports.push({ name, kind: 'global', idx: id });
        }
            
        if (!empty(x) && matchTagged(x[0], 'import')) {
            let names = x.shift();
            assert(names.length == 2, "bad import")
            let [mod, name] = names;
            assert(isStr(mod) && isStr(name), "bad import");
            let type = parseGlobalType(x);
            assert(empty(x), "bad import")
            imports.push({mod, name, kind: 'global', id, val: type});
            return;
        }

        let type = parseGlobalType(x);
        let init = parseInstructions(x, 'body');
        globals.push({id, type, init});
    }
    function parseStart(x) {
        let idx = parseIdx(x);
        assert(empty(x), "bad start");
        return idx;
    }

    let types = accum.type.map(parseType);
    let imports = accum.import.map(parseImport);
    let exports = accum.export.map(parseExport);
    let elems = accum.elem.map(parseElem);
    let datas = accum.data.map(parseData);
    let start = accum.start.map(parseStart);
    let funcs   = []; for (let x of accum.func)   { visitFunc(x); }
    let tables  = []; for (let x of accum.table)  { visitTable(x); }
    let mems    = []; for (let x of accum.memory) { visitMem(x); }
    let globals = []; for (let x of accum.global) { visitGlobal(x); }

    assert(start.length <= 1, "more than one start function");
    start = start[0];

    // resolve idx in: type uses, exports, elem, start, 

    let mod = { id, types, imports, funcs, tables, mems, globals, exports,
                start, elems, datas };
    let ids = {}
    for (let [k, v] of Object.entries(mod)) {
        ids[k] = {};
        if (v instanceof Array) {
            for (let [idx, x] of v.entries()) {
                if (isId(x.id)) { ids[k][x.id] = BigInt(idx); }
            }
        }
    }
    function resolveIdx(idx, kind) {
        if (isU32(idx)) { return idx; }
        let res = ids[kind][idx];
        assert(res !== undefined, `unbound identifier in ${kind}: ${idx}`);
        return res;
    }
    function resolveTypeUse(x) {
        if (x.idx !== undefined) {
            x.idx = resolveIdx(x.idx, 'types')
            assert(x.idx < mod.types.length, "type use idx out of range");
            // Preserve the names in the type use.
            if (empty(x.params)) { x.params = mod.types[x.idx].params; }
            x.results = mod.types[x.idx].results;
            return;
        }
        let sig = t => t.params.map(p=>p.type).join() + '->' + t.results.join();
        for (let [idx, t] of mod.types.entries()) {
            if (sig(x) === sig(t)) {
                x.idx = BigInt(idx);
                return;
            }
        }
        x.idx = BigInt(mod.types.length);
        mod.types.push(x);
    }
    function resolveBlockType(x) {
        if (x.idx !== undefined || (!empty(x.params) || x.results.length > 1)) {
            resolveTypeUse(x);
        }
    }
    function resolveInstructions(insts, locals=[], labels=[]) {
        function resolveLabel(id) {
            if (isU32(id)) { return id; }
            for (let [idx, x] of labels.entries()) {
                if (id == x) { return BigInt(idx); }
            }
            error(`unbound label: ${id}`);
        }
        function resolveLocal(id) {
            if (isU32(id)) { return id; }
            for (let [idx, local] of locals.entries()) {
                if (id == local.id) { return BigInt(idx); }
            }
            error(`unbound local: ${id}`);
        }
        for (let x of insts) {
            switch (x[0]) {
            case 'block':
            case 'loop': {
                let [inst, label, type, body] = x;
                resolveBlockType(type);
                labels.unshift(label);
                resolveInstructions(body, locals, labels);
                labels.shift();
                break;
            }
            case 'if': {
                let [inst, label, type, then, else_] = x;
                resolveBlockType(type);
                labels.unshift(label);
                resolveInstructions(then, locals, labels);
                resolveInstructions(else_, locals, labels);
                labels.shift();
                break;
            }
            case 'br':
            case 'br_if': {
                let [inst, idx] = x;
                x[1] = resolveLabel(idx);
                break;
            }
            case 'br_table': {
                let [inst, targets, default_] = x;
                x[1] = targets.map(resolveLabel);
                x[2] = resolveLabel(default_);
                break;
            }
            case 'call': {
                let [inst, idx] = x;
                x[1] = resolveIdx(idx, 'funcs');
                break;
            }
            case 'call_indirect': {
                let [inst, type] = x;
                resolveTypeUse(type);
                break;
            }
            case 'local.get':
            case 'local.set':
            case 'local.tee': {
                let [inst, idx] = x;
                x[1] = resolveLocal(idx);
                break;
            }
            case 'global.get':
            case 'global.set': {
                let [inst, idx] = x;
                x[1] = resolveIdx(idx, 'globals');
                break;
            }
            default:
                break;
            }
        }
    }
    for (let x of mod.imports) {
        switch (x.kind) {
        case 'func': resolveTypeUse(x.val); break;
        case 'table': break;
        case 'mem': break;
        case 'global': break;
        default: error("unreachable");
        }
    }
    for (let x of mod.funcs) {
        resolveTypeUse(x.type);
        resolveInstructions(x.body, x.type.params.concat(x.locals));
    }
    for (let x of mod.globals) {
        resolveInstructions(x.init);
    }
    for (let x of mod.exports) {
        switch (x.kind) {
        case 'func':   x.idx = resolveIdx(x.idx, 'funcs');   break;
        case 'table':  x.idx = resolveIdx(x.idx, 'tables');  break;
        case 'mem':    x.idx = resolveIdx(x.idx, 'mems');    break;
        case 'global': x.idx = resolveIdx(x.idx, 'globals'); break;
        default: error("unreachable");
        }
    }
    if (mod.start !== undefined) {
        mod.start = resolveIdx(mod.start, 'funcs');
    }
    for (let x of mod.elems) {
        x.idx = resolveIdx(x.idx, 'tables');
        resolveInstructions(x.offset);
        x.init.map(idx => resolveIdx(idx, 'funcs'));
    }
    for (let x of mod.datas) {
        x.idx = resolveIdx(x.idx, 'mems');
        resolveInstructions(x.offset);
    }
    return mod;
}

function assemble(mod) {
    function error(msg) { throw new Error(msg); }
    function assert(x, msg) {
        if (!x) { error(msg); }
        return x;
    }

    function emitU8(enc, x) { enc.u8(x); }
    function emitU32(enc, x) { enc.uleb(x); }
    function emitS32(enc, x) { enc.sleb(x); }
    function emitS64(enc, x) { enc.sleb(x); }
    function emitF32(enc, x) { error("unimplemented"); }
    function emitF64(enc, x) { error("unimplemented"); }

    function emitVec(enc, x, emit) {
        emitU32(enc, BigInt(x.length));
        for (let t of x) { emit(enc, t); }
    }

    function emitBytes(enc, emit) {
        let inner = new Encoder;
        emit(inner);
        let bytes = inner.finish();
        emitVec(enc, bytes, emitU8);
    }

    function emitValType(enc, x) {
        const valtypes = {i32:0x7F, i64:0x7E, f32:0x7D, f64:0x7C};
        emitU8(enc, assert(valtypes[x], `unknown type: ${x}`));
    }

    function emitResultType(enc, x) {
        emitVec(enc, x, emitValType);
    }

    function emitBlockType(enc, x) {
        if (x.params.length == 0) {
            if (x.results.length == 0) {
                emitU8(enc, 0x40);
                return;
            } else if (x.results.length == 1) {
                emitValType(enc, x.results[0]);
                return;
            }
        }
        emitU32(enc, x.idx);
    }

    function emitElemType(enc, x) {
        const types = { funcref: 0x70 };
        emitU8(enc, assert(types[x], `bad elem type: ${x}`));
    }

    function emitLimits(enc, x) {
        let {min, max} = x;
        if (min === undefined) min = 0n;
        if (max === undefined) {
            emitU8(enc, 0x00); emitU32(enc, min);
        } else {
            emitU8(enc, 0x01); emitU32(enc, min); emitU32(enc, max);
        }
    }

    function emitTableType(enc, x) {
        emitElemType(enc, x.elemtype)
        emitLimits(enc, x.limits)
    }

    function emitMemType(enc, x) {
        emitLimits(enc, x.limits);
    }

    function emitGlobalType(enc, x) {
        emitValType(enc, x.type);
        emitU8(enc, enc, x.mut ? 0x01 : 0x00);
    }

    function emitName(enc, x) {
        emitVec(enc, x, emitU8);
    }

    function emitInstruction(enc, x) {
        let [tag, ...args] = x;
        print(tag);
        assert(tag in opcodes, `bad instruction: ${x}`);
        emitU8(enc, opcodes[tag]);
        switch (tag) {
        case 'block':
        case 'loop':
            emitBlockType(enc, args[1]);
            emitInstructions(enc, args[2]);
            emitU8(enc, opcodes.end);
            break;
        case 'if':
            emitBlockType(enc, args[1]);
            emitInstructions(enc, args[2]);
            if (args[3].length) {
                emitU8(enc, opcodes['else']);
                emitInstructions(enc, args[3]);
            }
            emitU8(enc, opcodes.end);
            break;
        case 'br': case 'br_if':
        case 'call':
        case 'local.get': case 'local.set': case 'local.tee':
        case 'global.get': case 'global.tee':
            emitU32(enc, args[0]);
            break;
        case 'br_table':
            emitVec(enc, args[0], emitU32);
            emitU32(enc, args[1]);
            break;
        case 'call_indirect':
            emitU32(enc, args[0]);
            emitU8(enc, 0x00);
            break;
        case 'i32.load': case 'i64.load': case 'f32.load': case 'f64.load':
        case 'i32.load8_s': case 'i32.load8_u':
        case 'i32.load16_s': case 'i32.load16_u':
        case 'i64.load8_s': case 'i64.load8_u':
        case 'i64.load16_s': case 'i64.load16_u':
        case 'i64.load32_s': case 'i64.load32_u':
        case 'i32.store': case 'i64.store': case 'f32.store': case 'f64.store':
        case 'i32.store8': case 'i32.store16':
        case 'i64.store8': case 'i64.store16': case 'i64.store32':
            emitU32(enc, args[0].align);
            emitU32(enc, args[0].offset);
            break;
        case 'i32.const':
            emitS32(enc, args[0]);
            break;
        case 'i64.const':
            emitS64(enc, args[0]);
            break;
        case 'f32.const':
            emitF32(enc, args[0]);
            break;
        case 'f64.const':
            emitF64(enc, args[0]);
            break;
        default:
            break;
        }
    }

    function emitInstructions(enc, x) {
        for (let inst of x) { emitInstruction(enc, inst); }
    }

    function emitExpr(enc, x) {
        emitInstructions(enc, x);
        emitU8(enc, opcodes.end);
    }

    function emitFuncType(enc, x) {
        emitU8(enc, 0x60);
        emitResultType(enc, x.params.map(t=>{
            return t.type;
        }));
        emitResultType(enc, x.results);
    }

    function emitImport(enc, x) {
        emitName(enc, x.mod);
        emitName(enc, x.name);
        switch (x.kind) {
        case 'func':
            emitU8(enc, 0x00); emitU32(enc, x.val); break;
        case 'table':
            emitU8(enc, 0x01); emitTableType(enc, x.val); break;
        case 'mem':
            emitU8(enc, 0x02); emitMemType(enc, x.val); break;
        case 'global':
            emitU8(enc, 0x03); emitGlobalType(enc, x.val); break;
        default:
            error('unreachable');
        }
    }

    function emitFuncDecl(enc, x) {
        emitU32(enc, x.type.idx);
    }

    function emitTable(enc, x) {
        emitTableType(enc, x.type);
    }

    function emitMemory(enc, x) {
        emitMemType(enc, x.type);
    }

    function emitGlobal(enc, x) {
        emitGlobalType(enc, x.type);
        emitExpr(enc, x.init);
    }

    function emitExport(enc, x) {
        const kinds = { func: 0x00, table: 0x01, mem: 0x02, global: 0x03 };
        emitName(enc, x.name);
        assert(x.kind in kinds, `bad kind: ${x.kind}`)
        emitU8(enc, kinds[x.kind]);
        emitU32(enc, x.idx);
    }

    function emitElement(enc, x) {
        emitU32(enc, x.idx);
        emitExpr(enc, x.offset);
        emitVec(enc, x.init, emitU32);
    }

    function emitFuncDef(enc, x) {
        let compressedLocals = [];
        let headType;
        for (let local of x.locals) {
            if (local.type !== headType) {
                headType = local.type;
                compressedLocals.push({ count:0, type:headType });
            }
            compressedLocals[compressedLocals.length - 1].count++;
        }
        emitBytes(enc, enc => {
            emitVec(enc, compressedLocals, (enc, locals) => {
                emitU32(enc, locals.count);
                emitValType(enc, locals.type)
            });
            emitExpr(enc, x.body);
        });
    }

    function emitData(enc, x) {
        emitU32(enc, x.idx);
        emitExpr(enc, x.offset);
        emitBytes(enc, x.init);
    }

    function emitSection(enc, kind, emit) {
        const sections = { types: 1, imports: 2, funcs: 3, tables: 4,
                           mems: 5, globals: 6, exports: 7, start: 8,
                           elems: 9, code: 10, datas: 11 };
        emitU8(enc, assert(sections[kind], `bad section: ${kind}`));
        emitBytes(enc, emit);
    }

    function emitVecSection(enc, kind, emit) {
        let aliases = { code: 'funcs' }
        let vec = assert(mod[(kind in aliases) ? aliases[kind] : kind],
                         `bad section: ${kind}`)
        if (vec.length == 0) { return; }
        emitSection(enc, kind, enc => emitVec(enc, vec, emit));
    }

    function emitModule(emit) {
        const magic = [0x00, 0x61, 0x73, 0x6d]; // '\0asm'
        const version = [0x1, 0x0, 0x0, 0x0];
        let enc = new Encoder;
        enc.bytes(magic);
        enc.bytes(version);
        emit(enc);
        return enc.finish()
    }

    return emitModule(enc => {
        emitVecSection(enc, 'types', emitFuncType);
        emitVecSection(enc, 'imports', emitImport);
        emitVecSection(enc, 'funcs', emitFuncDecl);
        emitVecSection(enc, 'tables', emitTable);
        emitVecSection(enc, 'mems', emitMemory);
        emitVecSection(enc, 'globals', emitGlobal);
        emitVecSection(enc, 'exports', emitExport);
        if (mod.start !== undefined) {
            emitSection(enc, 'start', enc => emitU32(enc, mod.start));
        }
        emitVecSection(enc, 'elems', emitElement);
        emitVecSection(enc, 'code', emitFuncDef);
        emitVecSection(enc, 'datas', emitData);
    });
}

export default function wassemble(str) {
    return assemble(parse(read(str)));
}
