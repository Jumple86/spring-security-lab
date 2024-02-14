package org.ian.springsecuritylab.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

//@Component
public class VerificationCodeFilter implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if ("POST".equals(request.getMethod()) && "/doLogin".equals(request.getServletPath())) {
            String code = request.getParameter("code");
            String verifyCode = (String) request.getSession().getAttribute("verify_code");

            if (code == null || code.trim().isEmpty() || !verifyCode.equalsIgnoreCase(code)) {
                response.setContentType("application/json;charset=utf-8");
                PrintWriter writer = response.getWriter();
                writer.write("驗證碼錯誤");
                writer.flush();
                writer.close();

                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
