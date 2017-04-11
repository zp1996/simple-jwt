# simple-jwt

利用`node`实现的一个简单的`jwt`（仅仅做了有限的参数校验），帮助更好的理解`jwt`生成`token`的原理：
### API：
- `jwt.sign(payload, key, alg, options)`
   - payload   载荷
   - key  密钥
   - 加密算法类型，默认为`HS256`
   - 扩展配置，默认为`{}`
- `jwt.decode(token)`，转码`token`，得出`header`部分与`payload`部分
- `jwt.verify(token, key)`，验证`token`合法
    - 合法返回`payload`
    - 非法返回`false`
