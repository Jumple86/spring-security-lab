package org.ian.springsecuritylab.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Log4j2
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper;
    private SessionRegistry sessionRegistry;

    public LoginFilter() {
        super();
        objectMapper = new ObjectMapper();
    }

    @Autowired
    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String verifyCode = (String) request.getSession().getAttribute("verify_code");
        Map<String, String> requestParameters = new HashMap<>();
        if (MediaType.APPLICATION_JSON_VALUE.equals(request.getContentType())) {
            requestParameters = extractRequestParametersFromJson(request);
        } else {
            requestParameters = extractRequestParametersFromForm(request);
        }

        String code = requestParameters.get("code");
        checkoutVerifyCode(code, verifyCode);

        String username = requestParameters.get(getUsernameParameter());
        String password = requestParameters.get(getPasswordParameter());

        username = username != null ? username.trim() : "";
        password = password != null ? password : "";
        UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        this.setDetails(request, authRequest);

        Authentication authentication = this.getAuthenticationManager().authenticate(authRequest);
        sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
        return authentication;
    }

    private Map<String, String> extractRequestParametersFromJson(HttpServletRequest request) {
        Map<String, String> result = new HashMap<>();
        try {
            result = objectMapper.readValue(request.getReader(), Map.class);
        } catch (IOException e) {
            log.error(e.getMessage());
        }

        return result;
    }

    private Map<String, String> extractRequestParametersFromForm(HttpServletRequest request) {
        Map<String, String> result = new HashMap<>();
        result.put(getUsernameParameter(), request.getParameter(getUsernameParameter()));
        result.put(getPasswordParameter(), request.getParameter(getPasswordParameter()));
        result.put("code", request.getParameter("code"));

        return result;
    }

    private void checkoutVerifyCode(String code, String verifyCode) {
        if (code == null || code.trim().isEmpty() || !verifyCode.equalsIgnoreCase(code)) {
            throw new AuthenticationServiceException("驗證碼錯誤");
        }
    }
}
