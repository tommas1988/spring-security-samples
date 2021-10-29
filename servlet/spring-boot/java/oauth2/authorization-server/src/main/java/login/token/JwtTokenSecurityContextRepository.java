package login.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtTokenSecurityContextRepository implements SecurityContextRepository {
    public static final String SECURITY_CONTEXT_KEY = "login_token";

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        DecodedJWT token = buildTokenFromString(findTokenString(request));
        return new SecurityContextImpl(token == null ? null : new JwtAuthenticationToken(token));
    }

    // TODO: do some check
    private DecodedJWT buildTokenFromString(String tokenString) {
        if (tokenString == null)
            return null;

        DecodedJWT token = JWT.decode(tokenString);
        return token;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = context.getAuthentication();
        if (authentication == null) {
            return;
        }


        if (!(authentication instanceof JwtAuthenticationToken)) {
            throw new RuntimeException(String.format("Invalid Authentication type: %s", authentication.getClass()));
        }

        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
        if (jwtAuthenticationToken.isAuthenticated() && jwtAuthenticationToken.getToken() != null) {
            DecodedJWT token = jwtAuthenticationToken.getToken();
            Cookie cookie = new Cookie(SECURITY_CONTEXT_KEY, token.getToken());
            cookie.setHttpOnly(true);
            response.addCookie(cookie);
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return findTokenString(request) != null;
    }

    private String findTokenString(HttpServletRequest request) {
        if (request.getCookies() == null)
            return null;

        // TODO: need check expire ??
        for (Cookie cookie : request.getCookies()) {
            if (SECURITY_CONTEXT_KEY.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }
}
