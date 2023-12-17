package com.itheima.interceptor;


import com.alibaba.fastjson.JSONObject;
import com.itheima.pojo.Result;
import com.itheima.utils.JwtUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component  //交给ioc容器管理
public class LoginCheckInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object handler) throws Exception {
        // 1. 获取请求url
        String url=httpServletRequest.getRequestURL().toString();
        // 2. 判断请求url中是否包含login，如果包含，说明是登录操作，放行
        if(url.contains("login")){
            return true;
        }
        // 3. 获取请求头中的令牌（token）
        String token=httpServletRequest.getHeader("token");
        // 4. 判断令牌是否存在，如果不存在，返回错误结果（未登录）
        if(!StringUtils.hasLength(token)){
            Result result=Result.error("NOT_LOGIN");
            String json= JSONObject.toJSONString(result);
            httpServletResponse.setContentType("application/json;charset=utf-8");
            httpServletResponse.getWriter().write(json);
            return false;
        }
        // 5. 解析token，如果解析失败，返回错误结果（未登录）
        try{
            JwtUtils.parseJwt(token);
        }
        catch (Exception e){
            e.printStackTrace();
            Result result = Result.error("NOT_LOGIN");
            String json= JSONObject.toJSONString(result);
            httpServletResponse.setContentType("application/json;charset=utf-8");
            httpServletResponse.getWriter().write(json);
            return false;
        }
        // 6. 放行
        return true;





    }
}
