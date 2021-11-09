package login.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.util.WebUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    public static final String SECURITY_CONTEXT_KEY = "login_token";
    private static final String ALGORITHM_SECRET = "HS256 secret";

    private DecodedJWT jwtToken;
    private Authentication delegate;

    public JwtAuthenticationToken(DecodedJWT jwtToken) {
        super(null);
        setAuthenticated(true);
        this.jwtToken = jwtToken;

    }

    public JwtAuthenticationToken(Authentication delegate) {
        super(delegate.getAuthorities());
        this.delegate = delegate;
    }

    public DecodedJWT getToken() {
        return jwtToken;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    // TODO: do some check
    public static DecodedJWT getToken(HttpServletRequest request) {
        Cookie cookie = WebUtils.getCookie(request, SECURITY_CONTEXT_KEY);
        if (cookie == null)
            return null;

        DecodedJWT token = JWT.decode(cookie.getValue());
        Algorithm.HMAC256(ALGORITHM_SECRET).verify(token);
        return token;
    }

    public static boolean haveToken(HttpServletRequest request) {
        return WebUtils.getCookie(request, SECURITY_CONTEXT_KEY) != null;
    }

    public void saveToken(HttpServletResponse response) {
        String token = JWT.create()
                .withClaim("username", delegate.getName())
                .sign(Algorithm.HMAC256(ALGORITHM_SECRET));

        Cookie cookie = new Cookie(SECURITY_CONTEXT_KEY, token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }
}
