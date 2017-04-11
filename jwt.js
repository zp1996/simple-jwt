const crypto = require('crypto');
// 应用的加密算法
const algorithmMap = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256'
};
const typeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
};
// jwt不是严格意义上的base64,因为+,/,=在url中会被转义,导致token变得更长
const getBase64UrlEscape = str => (
  str.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/\=/g, '')
);

const getBase64UrlUnescape = str => {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+')
    .replace(/\_/g, '/');
};
// 将token转化为真正的base64编码
const getBase64Url = data => getBase64UrlEscape(
  new Buffer(JSON.stringify(data)).toString('base64')
);

const decodeBase64Url = str => JSON.parse(
  new Buffer(getBase64UrlUnescape(str), 'base64').toString()
);

const cryptoMethod = {
  hmac: (method, key, input) => {
    return crypto.createHmac(method, key)
      .update(input)
      .digest('base64')
  },
  sign: (method, input) => {
    return crypto.createSign(method)
      .update(input)
      .sign(key, 'base64');
  }
};

const sign = (input, key, method, type) => getBase64UrlEscape(
  cryptoMethod[type](method, key, input)
);

const verifyMethod = {
  hmac: (input, key, method, signStr) => signStr === sign(input, key, method, 'hmac'),
  sign: (input, key, method, sign) => {
    return crypto.createVerify(method)
      .update(input)
      .verify(key, getBase64UrlUnescape(sign), 'base64');
  }
};

const jwt = module.exports;
// 进行签名
jwt.sign = (payload, key, algorithm = 'HS256', options = {}) => {
  if (typeof payload !== 'object' || !key) throw new Error('参数传入有误');
  const signMethod = algorithmMap[algorithm],
    signType = typeMap[algorithm],
    header = {
      typ: 'JWT',
      alg: algorithm
    },
    res = [];
  options && options.header && Object.assign(header, options.header);
  // 过期时间默认为10分钟
  payload.iat || (payload.iat = Date.now() + 60000);
  res.push(getBase64Url(header));
  res.push(getBase64Url(payload));
  res.push(sign(res.join('.'), key, signMethod, signType));
  return res.join('.');
};
// 进行解析,将base64解析成对象
jwt.decode = (token) => {
  const segments = token.split('.');
  return {
    header: decodeBase64Url(segments[0]),
    payload: decodeBase64Url(segments[1])
  };
};
// 进行验证
jwt.verify = (token, key) => {
  if (!key) return false;
  const { header: { alg }, payload } = jwt.decode(token),
    method = algorithmMap[alg],
    type = typeMap[alg],
    segments = token.split('.');
  const flag = verifyMethod[type](
    [segments[0], segments[1]].join('.'),
    key,
    method,
    segments[2]
  );
  return flag && payload;
};
