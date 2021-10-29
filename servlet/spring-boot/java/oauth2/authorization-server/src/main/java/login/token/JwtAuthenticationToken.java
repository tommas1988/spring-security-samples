package login.token;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {
    private DecodedJWT jwtToken;

    public JwtAuthenticationToken(DecodedJWT jwtToken) {
        super(null);
        this.jwtToken = jwtToken;
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
}
