package login.token;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.web.context.SecurityContextRepository;

public class JwtAuthenticationConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<SecurityContextConfigurer<H>, H> {

    @Override
    public void init(H builder) throws Exception {
        builder.setSharedObject(SecurityContextRepository.class, new JwtTokenSecurityContextRepository());
    }
}
