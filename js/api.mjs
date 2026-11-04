// src/database.js
import { DatabaseSync } from "node:sqlite";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
var root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
var folder = process.env.MIAULAR_DATA_DIR || resolve(root, "data");
mkdirSync(folder, { recursive: true });
var database = new DatabaseSync(resolve(folder, "miaular.sqlite"));
database.exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
if (!database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get()) {
  database.exec(readFileSync(resolve(root, "db/schema.sql"), "utf8"));
}
var Statement = class _Statement {
  constructor(sql, params = []) {
    this.sql = sql;
    this.params = params;
  }
  bind(...params) {
    return new _Statement(this.sql, params);
  }
  async first() {
    return database.prepare(this.sql).get(...this.params) || null;
  }
  async all() {
    return { results: database.prepare(this.sql).all(...this.params) };
  }
  runSync() {
    const result = database.prepare(this.sql).run(...this.params);
    return { meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  }
  async run() {
    return this.runSync();
  }
};
var env = { DB: {
  prepare(sql) {
    return new Statement(sql);
  },
  async batch(statements) {
    database.exec("BEGIN IMMEDIATE");
    try {
      const results = statements.map((s) => s.runSync());
      database.exec("COMMIT");
      return results;
    } catch (error) {
      database.exec("ROLLBACK");
      throw error;
    }
  }
} };

// node_modules/bcryptjs/index.js
import nodeCrypto from "crypto";
var randomFallback = null;
function randomBytes(len) {
  try {
    return crypto.getRandomValues(new Uint8Array(len));
  } catch {
  }
  try {
    return nodeCrypto.randomBytes(len);
  } catch {
  }
  if (!randomFallback) {
    throw Error(
      "Neither WebCryptoAPI nor a crypto module is available. Use bcrypt.setRandomFallback to set an alternative"
    );
  }
  return randomFallback(len);
}
function setRandomFallback(random) {
  randomFallback = random;
}
function genSaltSync(rounds, seed_length) {
  rounds = rounds || GENSALT_DEFAULT_LOG2_ROUNDS;
  if (typeof rounds !== "number")
    throw Error(
      "Illegal arguments: " + typeof rounds + ", " + typeof seed_length
    );
  if (rounds < 4) rounds = 4;
  else if (rounds > 31) rounds = 31;
  var salt = [];
  salt.push("$2b$");
  if (rounds < 10) salt.push("0");
  salt.push(rounds.toString());
  salt.push("$");
  salt.push(base64_encode(randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN));
  return salt.join("");
}
function genSalt(rounds, seed_length, callback) {
  if (typeof seed_length === "function")
    callback = seed_length, seed_length = void 0;
  if (typeof rounds === "function") callback = rounds, rounds = void 0;
  if (typeof rounds === "undefined") rounds = GENSALT_DEFAULT_LOG2_ROUNDS;
  else if (typeof rounds !== "number")
    throw Error("illegal arguments: " + typeof rounds);
  function _async(callback2) {
    nextTick(function() {
      try {
        callback2(null, genSaltSync(rounds));
      } catch (err) {
        callback2(err);
      }
    });
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve2, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve2(res);
      });
    });
}
function hashSync(password, salt) {
  if (typeof salt === "undefined") salt = GENSALT_DEFAULT_LOG2_ROUNDS;
  if (typeof salt === "number") salt = genSaltSync(salt);
  if (typeof password !== "string" || typeof salt !== "string")
    throw Error("Illegal arguments: " + typeof password + ", " + typeof salt);
  return _hash(password, salt);
}
function hash(password, salt, callback, progressCallback) {
  function _async(callback2) {
    if (typeof password === "string" && typeof salt === "number")
      genSalt(salt, function(err, salt2) {
        _hash(password, salt2, callback2, progressCallback);
      });
    else if (typeof password === "string" && typeof salt === "string")
      _hash(password, salt, callback2, progressCallback);
    else
      nextTick(
        callback2.bind(
          this,
          Error("Illegal arguments: " + typeof password + ", " + typeof salt)
        )
      );
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve2, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve2(res);
      });
    });
}
function safeStringCompare(known, unknown) {
  var diff = known.length ^ unknown.length;
  for (var i = 0; i < known.length; ++i) {
    diff |= known.charCodeAt(i) ^ unknown.charCodeAt(i);
  }
  return diff === 0;
}
function compareSync(password, hash3) {
  if (typeof password !== "string" || typeof hash3 !== "string")
    throw Error("Illegal arguments: " + typeof password + ", " + typeof hash3);
  if (hash3.length !== 60) return false;
  return safeStringCompare(
    hashSync(password, hash3.substring(0, hash3.length - 31)),
    hash3
  );
}
function compare(password, hashValue, callback, progressCallback) {
  function _async(callback2) {
    if (typeof password !== "string" || typeof hashValue !== "string") {
      nextTick(
        callback2.bind(
          this,
          Error(
            "Illegal arguments: " + typeof password + ", " + typeof hashValue
          )
        )
      );
      return;
    }
    if (hashValue.length !== 60) {
      nextTick(callback2.bind(this, null, false));
      return;
    }
    hash(
      password,
      hashValue.substring(0, 29),
      function(err, comp) {
        if (err) callback2(err);
        else callback2(null, safeStringCompare(comp, hashValue));
      },
      progressCallback
    );
  }
  if (callback) {
    if (typeof callback !== "function")
      throw Error("Illegal callback: " + typeof callback);
    _async(callback);
  } else
    return new Promise(function(resolve2, reject) {
      _async(function(err, res) {
        if (err) {
          reject(err);
          return;
        }
        resolve2(res);
      });
    });
}
function getRounds(hash3) {
  if (typeof hash3 !== "string")
    throw Error("Illegal arguments: " + typeof hash3);
  return parseInt(hash3.split("$")[2], 10);
}
function getSalt(hash3) {
  if (typeof hash3 !== "string")
    throw Error("Illegal arguments: " + typeof hash3);
  if (hash3.length !== 60)
    throw Error("Illegal hash length: " + hash3.length + " != 60");
  return hash3.substring(0, 29);
}
function truncates(password) {
  if (typeof password !== "string")
    throw Error("Illegal arguments: " + typeof password);
  return utf8Length(password) > 72;
}
var nextTick = typeof setImmediate === "function" ? setImmediate : typeof scheduler === "object" && typeof scheduler.postTask === "function" ? scheduler.postTask.bind(scheduler) : setTimeout;
function utf8Length(string) {
  var len = 0, c = 0;
  for (var i = 0; i < string.length; ++i) {
    c = string.charCodeAt(i);
    if (c < 128) len += 1;
    else if (c < 2048) len += 2;
    else if ((c & 64512) === 55296 && (string.charCodeAt(i + 1) & 64512) === 56320) {
      ++i;
      len += 4;
    } else len += 3;
  }
  return len;
}
function utf8Array(string) {
  var offset = 0, c1, c2;
  var buffer = new Array(utf8Length(string));
  for (var i = 0, k = string.length; i < k; ++i) {
    c1 = string.charCodeAt(i);
    if (c1 < 128) {
      buffer[offset++] = c1;
    } else if (c1 < 2048) {
      buffer[offset++] = c1 >> 6 | 192;
      buffer[offset++] = c1 & 63 | 128;
    } else if ((c1 & 64512) === 55296 && ((c2 = string.charCodeAt(i + 1)) & 64512) === 56320) {
      c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
      ++i;
      buffer[offset++] = c1 >> 18 | 240;
      buffer[offset++] = c1 >> 12 & 63 | 128;
      buffer[offset++] = c1 >> 6 & 63 | 128;
      buffer[offset++] = c1 & 63 | 128;
    } else {
      buffer[offset++] = c1 >> 12 | 224;
      buffer[offset++] = c1 >> 6 & 63 | 128;
      buffer[offset++] = c1 & 63 | 128;
    }
  }
  return buffer;
}
var BASE64_CODE = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("");
var BASE64_INDEX = [
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  0,
  1,
  54,
  55,
  56,
  57,
  58,
  59,
  60,
  61,
  62,
  63,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  -1,
  -1,
  -1,
  -1,
  -1,
  -1,
  28,
  29,
  30,
  31,
  32,
  33,
  34,
  35,
  36,
  37,
  38,
  39,
  40,
  41,
  42,
  43,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
  -1,
  -1,
  -1,
  -1,
  -1
];
function base64_encode(b, len) {
  var off = 0, rs = [], c1, c2;
  if (len <= 0 || len > b.length) throw Error("Illegal len: " + len);
  while (off < len) {
    c1 = b[off++] & 255;
    rs.push(BASE64_CODE[c1 >> 2 & 63]);
    c1 = (c1 & 3) << 4;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 63]);
      break;
    }
    c2 = b[off++] & 255;
    c1 |= c2 >> 4 & 15;
    rs.push(BASE64_CODE[c1 & 63]);
    c1 = (c2 & 15) << 2;
    if (off >= len) {
      rs.push(BASE64_CODE[c1 & 63]);
      break;
    }
    c2 = b[off++] & 255;
    c1 |= c2 >> 6 & 3;
    rs.push(BASE64_CODE[c1 & 63]);
    rs.push(BASE64_CODE[c2 & 63]);
  }
  return rs.join("");
}
function base64_decode(s, len) {
  var off = 0, slen = s.length, olen = 0, rs = [], c1, c2, c3, c4, o, code;
  if (len <= 0) throw Error("Illegal len: " + len);
  while (off < slen - 1 && olen < len) {
    code = s.charCodeAt(off++);
    c1 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    code = s.charCodeAt(off++);
    c2 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    if (c1 == -1 || c2 == -1) break;
    o = c1 << 2 >>> 0;
    o |= (c2 & 48) >> 4;
    rs.push(String.fromCharCode(o));
    if (++olen >= len || off >= slen) break;
    code = s.charCodeAt(off++);
    c3 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    if (c3 == -1) break;
    o = (c2 & 15) << 4 >>> 0;
    o |= (c3 & 60) >> 2;
    rs.push(String.fromCharCode(o));
    if (++olen >= len || off >= slen) break;
    code = s.charCodeAt(off++);
    c4 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
    o = (c3 & 3) << 6 >>> 0;
    o |= c4;
    rs.push(String.fromCharCode(o));
    ++olen;
  }
  var res = [];
  for (off = 0; off < olen; off++) res.push(rs[off].charCodeAt(0));
  return res;
}
var BCRYPT_SALT_LEN = 16;
var GENSALT_DEFAULT_LOG2_ROUNDS = 10;
var BLOWFISH_NUM_ROUNDS = 16;
var MAX_EXECUTION_TIME = 100;
var P_ORIG = [
  608135816,
  2242054355,
  320440878,
  57701188,
  2752067618,
  698298832,
  137296536,
  3964562569,
  1160258022,
  953160567,
  3193202383,
  887688300,
  3232508343,
  3380367581,
  1065670069,
  3041331479,
  2450970073,
  2306472731
];
var S_ORIG = [
  3509652390,
  2564797868,
  805139163,
  3491422135,
  3101798381,
  1780907670,
  3128725573,
  4046225305,
  614570311,
  3012652279,
  134345442,
  2240740374,
  1667834072,
  1901547113,
  2757295779,
  4103290238,
  227898511,
  1921955416,
  1904987480,
  2182433518,
  2069144605,
  3260701109,
  2620446009,
  720527379,
  3318853667,
  677414384,
  3393288472,
  3101374703,
  2390351024,
  1614419982,
  1822297739,
  2954791486,
  3608508353,
  3174124327,
  2024746970,
  1432378464,
  3864339955,
  2857741204,
  1464375394,
  1676153920,
  1439316330,
  715854006,
  3033291828,
  289532110,
  2706671279,
  2087905683,
  3018724369,
  1668267050,
  732546397,
  1947742710,
  3462151702,
  2609353502,
  2950085171,
  1814351708,
  2050118529,
  680887927,
  999245976,
  1800124847,
  3300911131,
  1713906067,
  1641548236,
  4213287313,
  1216130144,
  1575780402,
  4018429277,
  3917837745,
  3693486850,
  3949271944,
  596196993,
  3549867205,
  258830323,
  2213823033,
  772490370,
  2760122372,
  1774776394,
  2652871518,
  566650946,
  4142492826,
  1728879713,
  2882767088,
  1783734482,
  3629395816,
  2517608232,
  2874225571,
  1861159788,
  326777828,
  3124490320,
  2130389656,
  2716951837,
  967770486,
  1724537150,
  2185432712,
  2364442137,
  1164943284,
  2105845187,
  998989502,
  3765401048,
  2244026483,
  1075463327,
  1455516326,
  1322494562,
  910128902,
  469688178,
  1117454909,
  936433444,
  3490320968,
  3675253459,
  1240580251,
  122909385,
  2157517691,
  634681816,
  4142456567,
  3825094682,
  3061402683,
  2540495037,
  79693498,
  3249098678,
  1084186820,
  1583128258,
  426386531,
  1761308591,
  1047286709,
  322548459,
  995290223,
  1845252383,
  2603652396,
  3431023940,
  2942221577,
  3202600964,
  3727903485,
  1712269319,
  422464435,
  3234572375,
  1170764815,
  3523960633,
  3117677531,
  1434042557,
  442511882,
  3600875718,
  1076654713,
  1738483198,
  4213154764,
  2393238008,
  3677496056,
  1014306527,
  4251020053,
  793779912,
  2902807211,
  842905082,
  4246964064,
  1395751752,
  1040244610,
  2656851899,
  3396308128,
  445077038,
  3742853595,
  3577915638,
  679411651,
  2892444358,
  2354009459,
  1767581616,
  3150600392,
  3791627101,
  3102740896,
  284835224,
  4246832056,
  1258075500,
  768725851,
  2589189241,
  3069724005,
  3532540348,
  1274779536,
  3789419226,
  2764799539,
  1660621633,
  3471099624,
  4011903706,
  913787905,
  3497959166,
  737222580,
  2514213453,
  2928710040,
  3937242737,
  1804850592,
  3499020752,
  2949064160,
  2386320175,
  2390070455,
  2415321851,
  4061277028,
  2290661394,
  2416832540,
  1336762016,
  1754252060,
  3520065937,
  3014181293,
  791618072,
  3188594551,
  3933548030,
  2332172193,
  3852520463,
  3043980520,
  413987798,
  3465142937,
  3030929376,
  4245938359,
  2093235073,
  3534596313,
  375366246,
  2157278981,
  2479649556,
  555357303,
  3870105701,
  2008414854,
  3344188149,
  4221384143,
  3956125452,
  2067696032,
  3594591187,
  2921233993,
  2428461,
  544322398,
  577241275,
  1471733935,
  610547355,
  4027169054,
  1432588573,
  1507829418,
  2025931657,
  3646575487,
  545086370,
  48609733,
  2200306550,
  1653985193,
  298326376,
  1316178497,
  3007786442,
  2064951626,
  458293330,
  2589141269,
  3591329599,
  3164325604,
  727753846,
  2179363840,
  146436021,
  1461446943,
  4069977195,
  705550613,
  3059967265,
  3887724982,
  4281599278,
  3313849956,
  1404054877,
  2845806497,
  146425753,
  1854211946,
  1266315497,
  3048417604,
  3681880366,
  3289982499,
  290971e4,
  1235738493,
  2632868024,
  2414719590,
  3970600049,
  1771706367,
  1449415276,
  3266420449,
  422970021,
  1963543593,
  2690192192,
  3826793022,
  1062508698,
  1531092325,
  1804592342,
  2583117782,
  2714934279,
  4024971509,
  1294809318,
  4028980673,
  1289560198,
  2221992742,
  1669523910,
  35572830,
  157838143,
  1052438473,
  1016535060,
  1802137761,
  1753167236,
  1386275462,
  3080475397,
  2857371447,
  1040679964,
  2145300060,
  2390574316,
  1461121720,
  2956646967,
  4031777805,
  4028374788,
  33600511,
  2920084762,
  1018524850,
  629373528,
  3691585981,
  3515945977,
  2091462646,
  2486323059,
  586499841,
  988145025,
  935516892,
  3367335476,
  2599673255,
  2839830854,
  265290510,
  3972581182,
  2759138881,
  3795373465,
  1005194799,
  847297441,
  406762289,
  1314163512,
  1332590856,
  1866599683,
  4127851711,
  750260880,
  613907577,
  1450815602,
  3165620655,
  3734664991,
  3650291728,
  3012275730,
  3704569646,
  1427272223,
  778793252,
  1343938022,
  2676280711,
  2052605720,
  1946737175,
  3164576444,
  3914038668,
  3967478842,
  3682934266,
  1661551462,
  3294938066,
  4011595847,
  840292616,
  3712170807,
  616741398,
  312560963,
  711312465,
  1351876610,
  322626781,
  1910503582,
  271666773,
  2175563734,
  1594956187,
  70604529,
  3617834859,
  1007753275,
  1495573769,
  4069517037,
  2549218298,
  2663038764,
  504708206,
  2263041392,
  3941167025,
  2249088522,
  1514023603,
  1998579484,
  1312622330,
  694541497,
  2582060303,
  2151582166,
  1382467621,
  776784248,
  2618340202,
  3323268794,
  2497899128,
  2784771155,
  503983604,
  4076293799,
  907881277,
  423175695,
  432175456,
  1378068232,
  4145222326,
  3954048622,
  3938656102,
  3820766613,
  2793130115,
  2977904593,
  26017576,
  3274890735,
  3194772133,
  1700274565,
  1756076034,
  4006520079,
  3677328699,
  720338349,
  1533947780,
  354530856,
  688349552,
  3973924725,
  1637815568,
  332179504,
  3949051286,
  53804574,
  2852348879,
  3044236432,
  1282449977,
  3583942155,
  3416972820,
  4006381244,
  1617046695,
  2628476075,
  3002303598,
  1686838959,
  431878346,
  2686675385,
  1700445008,
  1080580658,
  1009431731,
  832498133,
  3223435511,
  2605976345,
  2271191193,
  2516031870,
  1648197032,
  4164389018,
  2548247927,
  300782431,
  375919233,
  238389289,
  3353747414,
  2531188641,
  2019080857,
  1475708069,
  455242339,
  2609103871,
  448939670,
  3451063019,
  1395535956,
  2413381860,
  1841049896,
  1491858159,
  885456874,
  4264095073,
  4001119347,
  1565136089,
  3898914787,
  1108368660,
  540939232,
  1173283510,
  2745871338,
  3681308437,
  4207628240,
  3343053890,
  4016749493,
  1699691293,
  1103962373,
  3625875870,
  2256883143,
  3830138730,
  1031889488,
  3479347698,
  1535977030,
  4236805024,
  3251091107,
  2132092099,
  1774941330,
  1199868427,
  1452454533,
  157007616,
  2904115357,
  342012276,
  595725824,
  1480756522,
  206960106,
  497939518,
  591360097,
  863170706,
  2375253569,
  3596610801,
  1814182875,
  2094937945,
  3421402208,
  1082520231,
  3463918190,
  2785509508,
  435703966,
  3908032597,
  1641649973,
  2842273706,
  3305899714,
  1510255612,
  2148256476,
  2655287854,
  3276092548,
  4258621189,
  236887753,
  3681803219,
  274041037,
  1734335097,
  3815195456,
  3317970021,
  1899903192,
  1026095262,
  4050517792,
  356393447,
  2410691914,
  3873677099,
  3682840055,
  3913112168,
  2491498743,
  4132185628,
  2489919796,
  1091903735,
  1979897079,
  3170134830,
  3567386728,
  3557303409,
  857797738,
  1136121015,
  1342202287,
  507115054,
  2535736646,
  337727348,
  3213592640,
  1301675037,
  2528481711,
  1895095763,
  1721773893,
  3216771564,
  62756741,
  2142006736,
  835421444,
  2531993523,
  1442658625,
  3659876326,
  2882144922,
  676362277,
  1392781812,
  170690266,
  3921047035,
  1759253602,
  3611846912,
  1745797284,
  664899054,
  1329594018,
  3901205900,
  3045908486,
  2062866102,
  2865634940,
  3543621612,
  3464012697,
  1080764994,
  553557557,
  3656615353,
  3996768171,
  991055499,
  499776247,
  1265440854,
  648242737,
  3940784050,
  980351604,
  3713745714,
  1749149687,
  3396870395,
  4211799374,
  3640570775,
  1161844396,
  3125318951,
  1431517754,
  545492359,
  4268468663,
  3499529547,
  1437099964,
  2702547544,
  3433638243,
  2581715763,
  2787789398,
  1060185593,
  1593081372,
  2418618748,
  4260947970,
  69676912,
  2159744348,
  86519011,
  2512459080,
  3838209314,
  1220612927,
  3339683548,
  133810670,
  1090789135,
  1078426020,
  1569222167,
  845107691,
  3583754449,
  4072456591,
  1091646820,
  628848692,
  1613405280,
  3757631651,
  526609435,
  236106946,
  48312990,
  2942717905,
  3402727701,
  1797494240,
  859738849,
  992217954,
  4005476642,
  2243076622,
  3870952857,
  3732016268,
  765654824,
  3490871365,
  2511836413,
  1685915746,
  3888969200,
  1414112111,
  2273134842,
  3281911079,
  4080962846,
  172450625,
  2569994100,
  980381355,
  4109958455,
  2819808352,
  2716589560,
  2568741196,
  3681446669,
  3329971472,
  1835478071,
  660984891,
  3704678404,
  4045999559,
  3422617507,
  3040415634,
  1762651403,
  1719377915,
  3470491036,
  2693910283,
  3642056355,
  3138596744,
  1364962596,
  2073328063,
  1983633131,
  926494387,
  3423689081,
  2150032023,
  4096667949,
  1749200295,
  3328846651,
  309677260,
  2016342300,
  1779581495,
  3079819751,
  111262694,
  1274766160,
  443224088,
  298511866,
  1025883608,
  3806446537,
  1145181785,
  168956806,
  3641502830,
  3584813610,
  1689216846,
  3666258015,
  3200248200,
  1692713982,
  2646376535,
  4042768518,
  1618508792,
  1610833997,
  3523052358,
  4130873264,
  2001055236,
  3610705100,
  2202168115,
  4028541809,
  2961195399,
  1006657119,
  2006996926,
  3186142756,
  1430667929,
  3210227297,
  1314452623,
  4074634658,
  4101304120,
  2273951170,
  1399257539,
  3367210612,
  3027628629,
  1190975929,
  2062231137,
  2333990788,
  2221543033,
  2438960610,
  1181637006,
  548689776,
  2362791313,
  3372408396,
  3104550113,
  3145860560,
  296247880,
  1970579870,
  3078560182,
  3769228297,
  1714227617,
  3291629107,
  3898220290,
  166772364,
  1251581989,
  493813264,
  448347421,
  195405023,
  2709975567,
  677966185,
  3703036547,
  1463355134,
  2715995803,
  1338867538,
  1343315457,
  2802222074,
  2684532164,
  233230375,
  2599980071,
  2000651841,
  3277868038,
  1638401717,
  4028070440,
  3237316320,
  6314154,
  819756386,
  300326615,
  590932579,
  1405279636,
  3267499572,
  3150704214,
  2428286686,
  3959192993,
  3461946742,
  1862657033,
  1266418056,
  963775037,
  2089974820,
  2263052895,
  1917689273,
  448879540,
  3550394620,
  3981727096,
  150775221,
  3627908307,
  1303187396,
  508620638,
  2975983352,
  2726630617,
  1817252668,
  1876281319,
  1457606340,
  908771278,
  3720792119,
  3617206836,
  2455994898,
  1729034894,
  1080033504,
  976866871,
  3556439503,
  2881648439,
  1522871579,
  1555064734,
  1336096578,
  3548522304,
  2579274686,
  3574697629,
  3205460757,
  3593280638,
  3338716283,
  3079412587,
  564236357,
  2993598910,
  1781952180,
  1464380207,
  3163844217,
  3332601554,
  1699332808,
  1393555694,
  1183702653,
  3581086237,
  1288719814,
  691649499,
  2847557200,
  2895455976,
  3193889540,
  2717570544,
  1781354906,
  1676643554,
  2592534050,
  3230253752,
  1126444790,
  2770207658,
  2633158820,
  2210423226,
  2615765581,
  2414155088,
  3127139286,
  673620729,
  2805611233,
  1269405062,
  4015350505,
  3341807571,
  4149409754,
  1057255273,
  2012875353,
  2162469141,
  2276492801,
  2601117357,
  993977747,
  3918593370,
  2654263191,
  753973209,
  36408145,
  2530585658,
  25011837,
  3520020182,
  2088578344,
  530523599,
  2918365339,
  1524020338,
  1518925132,
  3760827505,
  3759777254,
  1202760957,
  3985898139,
  3906192525,
  674977740,
  4174734889,
  2031300136,
  2019492241,
  3983892565,
  4153806404,
  3822280332,
  352677332,
  2297720250,
  60907813,
  90501309,
  3286998549,
  1016092578,
  2535922412,
  2839152426,
  457141659,
  509813237,
  4120667899,
  652014361,
  1966332200,
  2975202805,
  55981186,
  2327461051,
  676427537,
  3255491064,
  2882294119,
  3433927263,
  1307055953,
  942726286,
  933058658,
  2468411793,
  3933900994,
  4215176142,
  1361170020,
  2001714738,
  2830558078,
  3274259782,
  1222529897,
  1679025792,
  2729314320,
  3714953764,
  1770335741,
  151462246,
  3013232138,
  1682292957,
  1483529935,
  471910574,
  1539241949,
  458788160,
  3436315007,
  1807016891,
  3718408830,
  978976581,
  1043663428,
  3165965781,
  1927990952,
  4200891579,
  2372276910,
  3208408903,
  3533431907,
  1412390302,
  2931980059,
  4132332400,
  1947078029,
  3881505623,
  4168226417,
  2941484381,
  1077988104,
  1320477388,
  886195818,
  18198404,
  3786409e3,
  2509781533,
  112762804,
  3463356488,
  1866414978,
  891333506,
  18488651,
  661792760,
  1628790961,
  3885187036,
  3141171499,
  876946877,
  2693282273,
  1372485963,
  791857591,
  2686433993,
  3759982718,
  3167212022,
  3472953795,
  2716379847,
  445679433,
  3561995674,
  3504004811,
  3574258232,
  54117162,
  3331405415,
  2381918588,
  3769707343,
  4154350007,
  1140177722,
  4074052095,
  668550556,
  3214352940,
  367459370,
  261225585,
  2610173221,
  4209349473,
  3468074219,
  3265815641,
  314222801,
  3066103646,
  3808782860,
  282218597,
  3406013506,
  3773591054,
  379116347,
  1285071038,
  846784868,
  2669647154,
  3771962079,
  3550491691,
  2305946142,
  453669953,
  1268987020,
  3317592352,
  3279303384,
  3744833421,
  2610507566,
  3859509063,
  266596637,
  3847019092,
  517658769,
  3462560207,
  3443424879,
  370717030,
  4247526661,
  2224018117,
  4143653529,
  4112773975,
  2788324899,
  2477274417,
  1456262402,
  2901442914,
  1517677493,
  1846949527,
  2295493580,
  3734397586,
  2176403920,
  1280348187,
  1908823572,
  3871786941,
  846861322,
  1172426758,
  3287448474,
  3383383037,
  1655181056,
  3139813346,
  901632758,
  1897031941,
  2986607138,
  3066810236,
  3447102507,
  1393639104,
  373351379,
  950779232,
  625454576,
  3124240540,
  4148612726,
  2007998917,
  544563296,
  2244738638,
  2330496472,
  2058025392,
  1291430526,
  424198748,
  50039436,
  29584100,
  3605783033,
  2429876329,
  2791104160,
  1057563949,
  3255363231,
  3075367218,
  3463963227,
  1469046755,
  985887462
];
var C_ORIG = [
  1332899944,
  1700884034,
  1701343084,
  1684370003,
  1668446532,
  1869963892
];
function _encipher(lr, off, P, S) {
  var n, l = lr[off], r = lr[off + 1];
  l ^= P[0];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[1];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[2];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[3];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[4];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[5];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[6];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[7];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[8];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[9];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[10];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[11];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[12];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[13];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[14];
  n = S[l >>> 24];
  n += S[256 | l >> 16 & 255];
  n ^= S[512 | l >> 8 & 255];
  n += S[768 | l & 255];
  r ^= n ^ P[15];
  n = S[r >>> 24];
  n += S[256 | r >> 16 & 255];
  n ^= S[512 | r >> 8 & 255];
  n += S[768 | r & 255];
  l ^= n ^ P[16];
  lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
  lr[off + 1] = l;
  return lr;
}
function _streamtoword(data, offp) {
  for (var i = 0, word = 0; i < 4; ++i)
    word = word << 8 | data[offp] & 255, offp = (offp + 1) % data.length;
  return { key: word, offp };
}
function _key(key, P, S) {
  var offset = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;
  for (var i = 0; i < plen; i++)
    sw = _streamtoword(key, offset), offset = sw.offp, P[i] = P[i] ^ sw.key;
  for (i = 0; i < plen; i += 2)
    lr = _encipher(lr, 0, P, S), P[i] = lr[0], P[i + 1] = lr[1];
  for (i = 0; i < slen; i += 2)
    lr = _encipher(lr, 0, P, S), S[i] = lr[0], S[i + 1] = lr[1];
}
function _ekskey(data, key, P, S) {
  var offp = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;
  for (var i = 0; i < plen; i++)
    sw = _streamtoword(key, offp), offp = sw.offp, P[i] = P[i] ^ sw.key;
  offp = 0;
  for (i = 0; i < plen; i += 2)
    sw = _streamtoword(data, offp), offp = sw.offp, lr[0] ^= sw.key, sw = _streamtoword(data, offp), offp = sw.offp, lr[1] ^= sw.key, lr = _encipher(lr, 0, P, S), P[i] = lr[0], P[i + 1] = lr[1];
  for (i = 0; i < slen; i += 2)
    sw = _streamtoword(data, offp), offp = sw.offp, lr[0] ^= sw.key, sw = _streamtoword(data, offp), offp = sw.offp, lr[1] ^= sw.key, lr = _encipher(lr, 0, P, S), S[i] = lr[0], S[i + 1] = lr[1];
}
function _crypt(b, salt, rounds, callback, progressCallback) {
  var cdata = C_ORIG.slice(), clen = cdata.length, err;
  if (rounds < 4 || rounds > 31) {
    err = Error("Illegal number of rounds (4-31): " + rounds);
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  if (salt.length !== BCRYPT_SALT_LEN) {
    err = Error(
      "Illegal salt length: " + salt.length + " != " + BCRYPT_SALT_LEN
    );
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  rounds = 1 << rounds >>> 0;
  var P, S, i = 0, j;
  if (typeof Int32Array === "function") {
    P = new Int32Array(P_ORIG);
    S = new Int32Array(S_ORIG);
  } else {
    P = P_ORIG.slice();
    S = S_ORIG.slice();
  }
  _ekskey(salt, b, P, S);
  function next() {
    if (progressCallback) progressCallback(i / rounds);
    if (i < rounds) {
      var start = Date.now();
      for (; i < rounds; ) {
        i = i + 1;
        _key(b, P, S);
        _key(salt, P, S);
        if (Date.now() - start > MAX_EXECUTION_TIME) break;
      }
    } else {
      for (i = 0; i < 64; i++)
        for (j = 0; j < clen >> 1; j++) _encipher(cdata, j << 1, P, S);
      var ret = [];
      for (i = 0; i < clen; i++)
        ret.push((cdata[i] >> 24 & 255) >>> 0), ret.push((cdata[i] >> 16 & 255) >>> 0), ret.push((cdata[i] >> 8 & 255) >>> 0), ret.push((cdata[i] & 255) >>> 0);
      if (callback) {
        callback(null, ret);
        return;
      } else return ret;
    }
    if (callback) nextTick(next);
  }
  if (typeof callback !== "undefined") {
    next();
  } else {
    var res;
    while (true) if (typeof (res = next()) !== "undefined") return res || [];
  }
}
function _hash(password, salt, callback, progressCallback) {
  var err;
  if (typeof password !== "string" || typeof salt !== "string") {
    err = Error("Invalid string / salt: Not a string");
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  var minor, offset;
  if (salt.charAt(0) !== "$" || salt.charAt(1) !== "2") {
    err = Error("Invalid salt version: " + salt.substring(0, 2));
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  if (salt.charAt(2) === "$") minor = String.fromCharCode(0), offset = 3;
  else {
    minor = salt.charAt(2);
    if (minor !== "a" && minor !== "b" && minor !== "y" || salt.charAt(3) !== "$") {
      err = Error("Invalid salt revision: " + salt.substring(2, 4));
      if (callback) {
        nextTick(callback.bind(this, err));
        return;
      } else throw err;
    }
    offset = 4;
  }
  if (salt.charAt(offset + 2) > "$") {
    err = Error("Missing salt rounds");
    if (callback) {
      nextTick(callback.bind(this, err));
      return;
    } else throw err;
  }
  var r1 = parseInt(salt.substring(offset, offset + 1), 10) * 10, r2 = parseInt(salt.substring(offset + 1, offset + 2), 10), rounds = r1 + r2, real_salt = salt.substring(offset + 3, offset + 25);
  password += minor >= "a" ? "\0" : "";
  var passwordb = utf8Array(password), saltb = base64_decode(real_salt, BCRYPT_SALT_LEN);
  function finish(bytes) {
    var res = [];
    res.push("$2");
    if (minor >= "a") res.push(minor);
    res.push("$");
    if (rounds < 10) res.push("0");
    res.push(rounds.toString());
    res.push("$");
    res.push(base64_encode(saltb, saltb.length));
    res.push(base64_encode(bytes, C_ORIG.length * 4 - 1));
    return res.join("");
  }
  if (typeof callback == "undefined")
    return finish(_crypt(passwordb, saltb, rounds));
  else {
    _crypt(
      passwordb,
      saltb,
      rounds,
      function(err2, bytes) {
        if (err2) callback(err2, null);
        else callback(null, finish(bytes));
      },
      progressCallback
    );
  }
}
function encodeBase64(bytes, length) {
  return base64_encode(bytes, length);
}
function decodeBase64(string, length) {
  return base64_decode(string, length);
}
var bcryptjs_default = {
  setRandomFallback,
  genSaltSync,
  genSalt,
  hashSync,
  hash,
  compareSync,
  compare,
  getRounds,
  getSalt,
  truncates,
  encodeBase64,
  decodeBase64
};

// src/photos.json
var photos_default = [{ image: "/cats/1.jpg", source: "https://www.pexels.com/photo/adorable-black-and-white-cat-sitting-indoors-32557420/", credit: "Photo by Sefa Demirta\u015F on Pexels", alt: "Cute black and white cat sitting upright on a cozy textured surface indoors." }, { image: "/cats/2.jpg", source: "https://www.pexels.com/photo/relaxed-gray-tabby-cat-lounging-by-the-window-33585484/", credit: "Photo by \u5927 \u8463 on Pexels", alt: "A serene gray tabby cat lounging by a sunny window indoors, capturing a moment of calm." }, { image: "/cats/3.jpg", source: "https://www.pexels.com/photo/close-up-portrait-of-ginger-tabby-cat-39495643/", credit: "Photo by FOX ^.\u11BD.^= \u222B on Pexels", alt: "A ginger tabby cat with striking eyes in a soft-focus indoor setting." }, { image: "/cats/4.jpg", source: "https://www.pexels.com/photo/playful-tabby-cat-lounging-on-yellow-sofa-39040811/", credit: "Photo by Ivett M on Pexels", alt: "A cute tabby cat relaxing and playing on a mustard yellow sofa indoors." }, { image: "/cats/5.jpg", source: "https://www.pexels.com/photo/cat-lying-on-the-sofa-19511759/", credit: "Photo by Johannes Rampp on Pexels", alt: "A serene gray cat lounging indoors, showcasing its distinctive yellow eyes and soft fur." }, { image: "/cats/6.jpg", source: "https://www.pexels.com/photo/playful-gray-cat-relaxing-indoors-on-colorful-blanket-35224529/", credit: "Photo by Rino Adamo on Pexels", alt: "A cute gray cat lounging comfortably on a vibrant patterned blanket indoors." }, { image: "/cats/7.jpg", source: "https://www.pexels.com/photo/calico-cat-resting-indoors-on-beige-floor-38728868/", credit: "Photo by Serkan Din\xE7 on Pexels", alt: "A calm calico cat lying on an indoor beige floor with a textured wall background." }, { image: "/cats/8.jpg", source: "https://www.pexels.com/photo/portrait-of-a-black-and-white-domestic-cat-with-yellow-eyes-lying-down-16412582/", credit: "Photo by Luiz Felipe on Pexels", alt: "Charming black and white cat lying comfortably indoors, displaying curiosity with bright eyes." }, { image: "/cats/9.jpg", source: "https://www.pexels.com/photo/calico-cat-relaxing-on-modern-sofa-indoors-30239303/", credit: "Photo by Kayla Dahl Maclean on Pexels", alt: "Adorable calico cat relaxing on a sofa indoors with a yellow pillow, peaceful ambiance." }, { image: "/cats/10.jpg", source: "https://www.pexels.com/photo/black-and-white-photo-of-cat-sleeping-on-sofa-37667519/", credit: "Photo by \u0130dil Ceren \xC7elikler on Pexels", alt: "A serene black and white photo of a cat peacefully sleeping on a grey sofa." }, { image: "/cats/11.jpg", source: "https://www.pexels.com/photo/brown-tabby-cat-lying-on-white-carpet-11238585/", credit: "Photo by Mathias Reding on Pexels", alt: "Charming portrait of a tabby cat lying on a soft textured surface, wide-eyed and relaxed." }, { image: "/cats/12.jpg", source: "https://www.pexels.com/photo/british-shorthair-cat-wearing-sweater-11187356/", credit: "Photo by Created Stories on Pexels", alt: "Charming British Shorthair cat wearing a knitted sweater, lounging comfortably inside a home." }, { image: "/cats/13.jpg", source: "https://www.pexels.com/photo/a-close-up-shot-of-a-tabby-cat-lying-down-13081375/", credit: "Photo by Amar Preciado on Pexels", alt: "Close-up of a calm tabby cat lounging, showcasing its beautiful striped fur." }, { image: "/cats/14.jpg", source: "https://www.pexels.com/photo/black-gray-and-white-tabby-cat-resting-in-brown-red-black-and-white-rug-116835/", credit: "Photo by lord_ photon on Pexels", alt: "Cute tabby cat lying on a vibrant carpet in a cozy indoor setting." }, { image: "/cats/15.jpg", source: "https://www.pexels.com/photo/brown-cat-leaning-on-black-wall-9088489/", credit: "Photo by NRK clickz on Pexels", alt: "A serene ginger domestic cat lying down, showcasing detailed fur and whiskers." }, { image: "/cats/16.jpg", source: "https://www.pexels.com/photo/beautiful-bengal-cat-relaxing-on-yellow-sofa-30002390/", credit: "Photo by Helena Jankovi\u010Dov\xE1 Kov\xE1\u010Dov\xE1 on Pexels", alt: "A striking Bengal cat with distinctive fur pattern lounging on a vibrant yellow sofa indoors." }, { image: "/cats/17.jpg", source: "https://www.pexels.com/photo/curious-purebred-cat-resting-on-couch-at-home-6001401/", credit: "Photo by Sam Lion on Pexels", alt: "A calm cat lounging on a sofa in a cozy living room setting with soft focus." }, { image: "/cats/18.jpg", source: "https://www.pexels.com/photo/close-up-of-cat-16476075/", credit: "Photo by Gabriel Ramos on Pexels", alt: "Elegant close-up portrait of a gray cat showing captivating green eyes, perfect for pet lovers." }, { image: "/cats/19.jpg", source: "https://www.pexels.com/photo/curious-kitten-playing-indoors-with-toy-ball-34719941/", credit: "Photo by Primitive Spaces on Pexels", alt: "Adorable tabby kitten on carpet looking curious near a toy ball." }, { image: "/cats/20.jpg", source: "https://www.pexels.com/photo/a-kitten-sitting-on-the-ground-17457980/", credit: "Photo by Atahan Demir on Pexels", alt: "Cute white and orange kitten sitting on an outdoor concrete floor." }];

// src/cats.js
var names = ["Luna", "Oliver", "Amora", "Chico", "Nina", "Simba", "Bento", "Mel", "Tom", "Mia", "Pipoca", "Nino", "Jade", "Theo", "Frida", "Romeu", "Cacau", "Bidu", "Flora", "Fred"];
var stories = ["Uma companhia tranquila para descobrir o mundo no seu pr\xF3prio ritmo.", "Curiosidade e energia para transformar pequenos momentos em divers\xE3o.", "Carinho, brincadeiras e uma janela ensolarada fazem parte de um lar acolhedor.", "Um companheiro que merece paci\xEAncia, respeito e uma rotina cheia de cuidado."];
var initialCats = photos_default.slice(0, 10).map((p, i) => ({ id: String(i + 1), name: names[i], age: [8, 24, 36, 10, 18, 48, 6, 72, 30, 12, 5, 60, 20, 40, 9, 84, 15, 32, 7, 54][i], sex: i % 2 ? "Macho" : "F\xEAmea", breed: "Sem ra\xE7a definida", size: i % 3 ? "M\xE9dio" : "Pequeno", description: stories[i % 4] + " Perfil ilustrativo criado para demonstrar a plataforma acad\xEAmica. A fotografia \xE9 real, mas n\xE3o representa um an\xFAncio verificado de ado\xE7\xE3o.", location: "Franca, SP \xB7 localiza\xE7\xE3o ilustrativa", health: "N\xE3o informado. Vacina\xE7\xE3o, castra\xE7\xE3o e testes FIV/FeLV devem ser confirmados com o respons\xE1vel antes de uma ado\xE7\xE3o real.", image: p.image, credit: p.credit, source: p.source, status: "Dispon\xEDvel", owner: "academic" }));

// src/api.js
var db = () => env.DB;
var one = async (q, ...a) => db().prepare(q).bind(...a).first();
var all = async (q, ...a) => (await db().prepare(q).bind(...a).all()).results;
var run = async (q, ...a) => db().prepare(q).bind(...a).run();
var clean = (v, max = 200) => typeof v === "string" ? v.trim().slice(0, max) : "";
var hash2 = async (s) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))).map((b) => b.toString(16).padStart(2, "0")).join("");
var reply = (data, status = 200, cookie) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...cookie ? { "Set-Cookie": cookie } : {} } });
var safe = (u) => u ? { id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role, active: u.active } : null;
async function current(req) {
  const t = req.headers.get("cookie")?.match(/(?:^|; )miaular=([^;]+)/)?.[1];
  if (!t) return null;
  return one("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires>? AND u.active=1 AND u.platform=?", await hash2(t), Date.now(), "local");
}
async function seed() {
  const stmts = initialCats.map((c) => db().prepare("INSERT OR IGNORE INTO cats (id,name,age,sex,breed,size,description,location,health,image,credit,source,status,owner) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM settings WHERE id='seeded')").bind(...Object.values(c)));
  await db().batch([...stmts, db().prepare("INSERT OR IGNORE INTO settings (id,value) VALUES ('seeded','1')")]);
}
async function GET(req) {
  try {
    await seed();
    const u = await current(req);
    const cats = await all("SELECT * FROM cats ORDER BY CAST(id AS INTEGER),name");
    let requests = [];
    let users = [];
    if (u) {
      requests = await all(`SELECT r.*, c.name AS cat_name, c.image AS cat_image, u.name AS user_name, u.email AS user_email, u.phone AS user_phone FROM requests r JOIN cats c ON c.id=r.cat_id JOIN users u ON u.id=r.user_id WHERE ${u.role === "Administrador" ? "1=1" : u.role === "Respons\xE1vel" ? "c.owner=?" : "r.user_id=?"} ORDER BY r.created DESC`, ...u.role === "Administrador" ? [] : [u.id]);
      if (u.role === "Administrador") users = await all("SELECT id,name,email,phone,role,active FROM users");
    }
    return reply({ cats, user: safe(u), requests, users, setup: !await one("SELECT id FROM users LIMIT 1") });
  } catch {
    return reply({ error: "N\xE3o foi poss\xEDvel carregar os dados. Tente novamente." }, 500);
  }
}
async function POST(req) {
  try {
    const url = new URL(req.url);
    if (req.headers.get("origin") !== url.origin) return reply({ error: "Origem n\xE3o autorizada." }, 403);
    if (!req.headers.get("content-type")?.includes("application/json")) return reply({ error: "Formato inv\xE1lido." }, 415);
    const raw = await req.text();
    if (raw.length > 22e5) return reply({ error: "Arquivo ou formul\xE1rio muito grande." }, 413);
    const b = JSON.parse(raw);
    const platform = "local";
    const u = await current(req);
    const action = b.action;
    if (action === "register" || action === "login" || action === "reset") {
      const key = await hash2(platform + ":auth:" + Math.floor(Date.now() / 9e5));
      await run("INSERT INTO limits(id,count,expires) VALUES(?,1,?) ON CONFLICT(id) DO UPDATE SET count=count+1", key, Date.now() + 9e5);
      if ((await one("SELECT count FROM limits WHERE id=?", key)).count > 15) return reply({ error: "Muitas tentativas. Aguarde 15 minutos." }, 429);
      await run("DELETE FROM limits WHERE expires<?", Date.now());
      const email = clean(b.email).toLowerCase();
      const password = clean(b.password, 128);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10) return reply({ error: "Use um e-mail v\xE1lido e uma senha de pelo menos 10 caracteres." }, 400);
      if (action === "register") {
        const name = clean(b.name, 100), phone = clean(b.phone, 30);
        if (name.length < 3 || phone.replace(/\D/g, "").length < 10) return reply({ error: "Informe nome completo e telefone v\xE1lido." }, 400);
        if (await one("SELECT id FROM users WHERE email=?", email)) return reply({ error: "E-mail j\xE1 cadastrado no sistema." }, 409);
        const id = crypto.randomUUID();
        const role = b.role === "Respons\xE1vel" ? "Respons\xE1vel" : "Adotante";
        await run("INSERT INTO users(id,name,email,phone,password,role,active,platform) VALUES(?,?,?,?,?,?,1,?)", id, name, email, phone, await bcryptjs_default.hash(password, 10), role, platform);
        await run("INSERT OR IGNORE INTO settings(id,value) VALUES ('workspace_owner',?)", platform);
        const owner = await one("SELECT value FROM settings WHERE id='workspace_owner'");
        if (owner.value === platform && !await one("SELECT id FROM users WHERE role='Administrador'")) await run("UPDATE users SET role='Administrador' WHERE id=?", id);
        return reply({ ok: true, message: "Conta criada. Entre para continuar." });
      }
      if (action === "reset") {
        const own = await one("SELECT id FROM users WHERE email=? AND active=1 AND platform=?", email, platform);
        if (!own) return reply({ error: "E-mail ou senha atual inv\xE1lidos." }, 400);
        const resetAccount = await one("SELECT password FROM users WHERE id=?", own.id);
        if (!await bcryptjs_default.compare(clean(b.currentPassword, 128), resetAccount.password)) return reply({ error: "E-mail ou senha atual inv\xE1lidos." }, 400);
        await db().batch([db().prepare("UPDATE users SET password=? WHERE id=?").bind(await bcryptjs_default.hash(password, 10), own.id), db().prepare("DELETE FROM sessions WHERE user_id=?").bind(own.id)]);
        return reply({ ok: true });
      }
      const account = await one("SELECT * FROM users WHERE email=? AND active=1 AND platform=?", email, platform);
      if (!account || !await bcryptjs_default.compare(password, account.password)) return reply({ error: "E-mail ou senha inv\xE1lidos." }, 401);
      const token = crypto.randomUUID() + crypto.randomUUID();
      await run("DELETE FROM sessions WHERE expires<?", Date.now());
      await run("INSERT INTO sessions(id,user_id,expires) VALUES(?,?,?)", await hash2(token), account.id, Date.now() + 8 * 36e5);
      return reply({ ok: true }, 200, `miaular=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`);
    }
    if (!u) return reply({ error: "Fa\xE7a login para continuar." }, 401);
    if (action === "logout") {
      const t = req.headers.get("cookie")?.match(/(?:^|; )miaular=([^;]+)/)?.[1];
      if (t) await run("DELETE FROM sessions WHERE id=?", await hash2(t));
      return reply({ ok: true }, 200, "miaular=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    }
    if (action === "adopt") {
      if (u.role !== "Adotante") return reply({ error: "Somente adotantes podem solicitar uma ado\xE7\xE3o." }, 403);
      const answers = clean(b.answers, 4e3);
      if (answers.length < 30) return reply({ error: "Complete o question\xE1rio de inten\xE7\xE3o de ado\xE7\xE3o." }, 400);
      const result = await run("INSERT INTO requests(id,cat_id,user_id,answers,status,reason,created) SELECT ?,?,?,?,'Em an\xE1lise','',? WHERE EXISTS(SELECT 1 FROM cats WHERE id=? AND status='Dispon\xEDvel') AND NOT EXISTS(SELECT 1 FROM requests WHERE cat_id=? AND user_id=? AND status='Em an\xE1lise')", crypto.randomUUID(), b.catId, u.id, answers, (/* @__PURE__ */ new Date()).toISOString(), b.catId, b.catId, u.id);
      if (!result.meta.changes) return reply({ error: "Gato indispon\xEDvel ou voc\xEA j\xE1 tem uma solicita\xE7\xE3o em an\xE1lise para ele." }, 409);
      return reply({ ok: true });
    }
    if (action === "decide") {
      const r = await one("SELECT r.*,c.owner FROM requests r JOIN cats c ON c.id=r.cat_id WHERE r.id=?", b.id);
      if (!r || !(u.role === "Administrador" || u.role === "Respons\xE1vel" && r.owner === u.id)) return reply({ error: "Acesso n\xE3o autorizado." }, 403);
      if (r.status !== "Em an\xE1lise") return reply({ error: "Essa solicita\xE7\xE3o j\xE1 foi analisada." }, 409);
      if (b.approve) {
        await db().batch([db().prepare("UPDATE cats SET status='Adotado' WHERE id=? AND status IN ('Dispon\xEDvel','Em processo de ado\xE7\xE3o') AND EXISTS(SELECT 1 FROM requests WHERE id=? AND status='Em an\xE1lise')").bind(r.cat_id, r.id), db().prepare("UPDATE requests SET status='Aprovada',reason='' WHERE id=? AND status='Em an\xE1lise' AND EXISTS(SELECT 1 FROM cats WHERE id=? AND status='Adotado') AND NOT EXISTS(SELECT 1 FROM requests WHERE cat_id=? AND status='Aprovada')").bind(r.id, r.cat_id, r.cat_id), db().prepare("UPDATE requests SET status='Recusada',reason='Outra solicita\xE7\xE3o foi aprovada para este gato.' WHERE cat_id=? AND id<>? AND status='Em an\xE1lise' AND EXISTS(SELECT 1 FROM requests WHERE id=? AND status='Aprovada')").bind(r.cat_id, r.id, r.id)]);
      } else await run("UPDATE requests SET status='Recusada',reason=? WHERE id=? AND status='Em an\xE1lise'", clean(b.reason, 500), r.id);
      return reply({ ok: true });
    }
    if (action === "user") {
      if (u.role !== "Administrador") return reply({ error: "Acesso exclusivo do administrador." }, 403);
      if (b.id === u.id) return reply({ error: "Sua pr\xF3pria conta administrativa n\xE3o pode ser desativada ou rebaixada." }, 400);
      if (!["Adotante", "Respons\xE1vel", "Administrador"].includes(b.role)) return reply({ error: "Perfil inv\xE1lido." }, 400);
      const name = clean(b.name, 100), email = clean(b.email).toLowerCase(), phone = clean(b.phone, 30);
      if (name.length < 3 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || phone.replace(/\D/g, "").length < 10) return reply({ error: "Dados de usu\xE1rio inv\xE1lidos." }, 400);
      if (await one("SELECT id FROM users WHERE email=? AND id<>?", email, b.id)) return reply({ error: "E-mail j\xE1 cadastrado." }, 409);
      await db().batch([db().prepare("UPDATE users SET name=?,email=?,phone=?,role=?,active=? WHERE id=?").bind(name, email, phone, b.role, b.active ? 1 : 0, b.id), db().prepare("DELETE FROM sessions WHERE user_id=?").bind(b.id)]);
      return reply({ ok: true });
    }
    if (["saveCat", "deleteCat", "status"].includes(action)) {
      if (!["Respons\xE1vel", "Administrador"].includes(u.role)) return reply({ error: "Acesso n\xE3o autorizado." }, 403);
      const c = b.id ? await one("SELECT * FROM cats WHERE id=?", b.id) : null;
      if (b.id && (!c || c.owner !== u.id && u.role !== "Administrador")) return reply({ error: "Voc\xEA n\xE3o administra este gato." }, 403);
      if (action === "deleteCat") {
        await db().batch([db().prepare("DELETE FROM requests WHERE cat_id=?").bind(b.id), db().prepare("DELETE FROM cats WHERE id=?").bind(b.id)]);
        return reply({ ok: true });
      }
      if (action === "status") {
        if (!["Dispon\xEDvel", "Em processo de ado\xE7\xE3o", "Adotado"].includes(b.status)) return reply({ error: "Status inv\xE1lido." }, 400);
        if (c.status === "Adotado" && b.status !== "Adotado") return reply({ error: "Ado\xE7\xF5es conclu\xEDdas n\xE3o podem ser reabertas." }, 409);
        await db().batch([db().prepare("UPDATE cats SET status=? WHERE id=?").bind(b.status, b.id), db().prepare("UPDATE requests SET status='Recusada',reason='Cadastro marcado como adotado pelo respons\xE1vel.' WHERE cat_id=? AND status='Em an\xE1lise' AND ?='Adotado'").bind(b.id, b.status)]);
        return reply({ ok: true });
      }
      const image = clean(b.image, 2e6);
      if (!(/^\/cats\/\d+\.jpg$/.test(image) || /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(image))) return reply({ error: "Envie uma foto JPG, PNG ou WebP de at\xE9 1 MB." }, 400);
      if (image.startsWith("data:")) {
        let bytes;
        try {
          bytes = atob(image.split(",")[1]).slice(0, 16);
        } catch {
          return reply({ error: "Fotografia inv\xE1lida." }, 400);
        }
        const valid = image.startsWith("data:image/jpeg;") ? bytes.charCodeAt(0) === 255 && bytes.charCodeAt(1) === 216 && bytes.charCodeAt(2) === 255 : image.startsWith("data:image/png;") ? bytes.charCodeAt(0) === 137 && bytes.slice(1, 4) === "PNG" : bytes.slice(0, 4) === "RIFF" && bytes.slice(8, 12) === "WEBP";
        if (!valid) return reply({ error: "O conte\xFAdo n\xE3o corresponde a uma fotografia v\xE1lida." }, 400);
      }
      if (!clean(b.name) || !clean(b.description) || !clean(b.location) || !["Macho", "F\xEAmea"].includes(b.sex) || !["Pequeno", "M\xE9dio", "Grande"].includes(b.size) || !Number.isInteger(Number(b.age)) || Number(b.age) < 0 || Number(b.age) > 360) return reply({ error: "Preencha todos os campos com dados v\xE1lidos." }, 400);
      const id = b.id || crypto.randomUUID();
      const values = [clean(b.name, 60), Number(b.age), b.sex, clean(b.breed, 60) || "Sem ra\xE7a definida", b.size, clean(b.description, 4e3), clean(b.location, 120), clean(b.health, 1e3) || "N\xE3o informado", image, c?.credit || "Fotografia enviada pelo respons\xE1vel", c?.source || "", id];
      if (c) await run("UPDATE cats SET name=?,age=?,sex=?,breed=?,size=?,description=?,location=?,health=?,image=?,credit=?,source=? WHERE id=?", ...values);
      else {
        const inserted = await run("INSERT INTO cats(name,age,sex,breed,size,description,location,health,image,credit,source,id,status,owner) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,'Dispon\xEDvel',? WHERE (SELECT count(*) FROM cats)<10", ...values, u.id);
        if (!inserted.meta.changes) return reply({ error: "O cat\xE1logo est\xE1 limitado a 10 gatos. Remova um cadastro antes de adicionar outro." }, 409);
      }
      return reply({ ok: true });
    }
    return reply({ error: "A\xE7\xE3o desconhecida." }, 400);
  } catch {
    return reply({ error: "N\xE3o foi poss\xEDvel concluir a a\xE7\xE3o. Revise os dados e tente novamente." }, 500);
  }
}
export {
  GET,
  POST
};
