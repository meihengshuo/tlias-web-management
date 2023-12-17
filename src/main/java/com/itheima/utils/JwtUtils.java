package com.itheima.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.Map;

public class JwtUtils {

    //密钥
    private static String signKey = "itheima";
    //过期时间
    private static Long expire = 43200000L;



    /**
     * 生成令牌
     */
    public static String generateJwt(Map<String,Object> claims){
        return Jwts.builder()
                .addClaims(claims)//载荷
                .signWith(SignatureAlgorithm.HS256,signKey)//算法和签名密钥
                .setExpiration(new Date(System.currentTimeMillis()+expire))//过期时间
                .compact();//得到字符串类型值
    }

    /**
     * 解析令牌
     */
    public static Claims parseJwt(String jwt){
        return Jwts.parser()//解析
                .setSigningKey(signKey)//签名密钥
                .parseClaimsJws(jwt)//令牌token
                .getBody();//得到令牌的第二部分
    }


}
