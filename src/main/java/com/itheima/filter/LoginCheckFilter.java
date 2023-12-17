package com.itheima.filter;


import com.alibaba.fastjson.JSONObject;
import com.itheima.pojo.Result;
import com.itheima.utils.JwtUtils;
import org.springframework.util.StringUtils;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter(urlPatterns = "/*")
public class LoginCheckFilter implements Filter {


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest=(HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse=(HttpServletResponse) servletResponse;
        // 1. 获取请求url
        String url=httpServletRequest.getRequestURL().toString();
        // 2. 判断请求url中是否包含login，如果包含，说明是登录操作，放行
        if(url.contains("login")){
            chain.doFilter(httpServletRequest,httpServletResponse);
            return;
        }
        // 3. 获取请求头中的令牌（token）
        String token=httpServletRequest.getHeader("token");
        // 4. 判断令牌是否存在，如果不存在，返回错误结果（未登录）
        if(!StringUtils.hasLength(token)){
            Result result=Result.error("NOT_LOGIN");
            String json= JSONObject.toJSONString(result);
            httpServletResponse.setContentType("application/json;charset=utf-8");
            httpServletResponse.getWriter().write(json);
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
            return;
        }
        // 6. 放行
        chain.doFilter(httpServletRequest,httpServletResponse);

    }
}
