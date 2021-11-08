package configuration;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

public abstract class SessionlessWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    private boolean removeDefaultSessionFunction;

    protected SessionlessWebSecurityConfigurerAdapter() {
        super(false);
        this.removeDefaultSessionFunction = true;
    }

    protected SessionlessWebSecurityConfigurerAdapter(boolean disableDefaults) {
        super(disableDefaults);
        this.removeDefaultSessionFunction = !disableDefaults;
    }

    @Override
    public void init(WebSecurity web) throws Exception {
        if (removeDefaultSessionFunction) {
            removeSessionRelatedFunction(getHttp());
        }
        super.init(web);
    }

    private void removeSessionRelatedFunction(HttpSecurity httpSecurity) {
        // csrf()
        httpSecurity.getConfigurer(CsrfConfigurer.class).csrfTokenRepository(new LazyCsrfTokenRepository(new CookieCsrfTokenRepository()));

        // sessionManagement()
        httpSecurity.removeConfigurer(SessionManagementConfigurer.class);

        // securityContext()
        // TODO: securityContextRepository should be configured in this class
        httpSecurity.getConfigurer(SecurityContextConfigurer.class).securityContextRepository(new NullSecurityContextRepository());

        // requestCache()
        httpSecurity.setSharedObject(RequestCache.class, new CookieRequestCache());
    }
}
