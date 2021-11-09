package login.token;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtTokenSecurityContextRepository implements SecurityContextRepository {
    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        DecodedJWT token = JwtAuthenticationToken.getToken(request);
        return new SecurityContextImpl(token == null ? null : new JwtAuthenticationToken(token));
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        // should be saved in JwtAuthenticationSuccessHandler.onAuthenticationSuccess
        // TODO: do some checks?
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return JwtAuthenticationToken.haveToken(request);
    }
}
