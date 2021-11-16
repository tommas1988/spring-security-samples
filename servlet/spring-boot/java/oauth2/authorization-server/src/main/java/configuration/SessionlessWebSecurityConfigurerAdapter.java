package configuration;

import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public abstract class SessionlessWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);

        web.ignoring().requestMatchers(faviconMatcher());
    }

    protected RequestMatcher faviconMatcher() {
        return new AntPathRequestMatcher("/favicon.ico");
    }

    // must be called in subclass
    @Override
    protected final void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new SessionCreationCheckFilter(), ChannelProcessingFilter.class);
        doConfigure(http);
    }

    abstract protected void doConfigure(HttpSecurity http) throws Exception;

    @Override
    public void init(WebSecurity web) throws Exception {
        HttpSecurity httpSecurity = getHttp();
        SecurityConfigurer configurer;

        // csrf configuration
        if ((configurer = httpSecurity.getConfigurer(CsrfConfigurer.class)) != null) {
            ((CsrfConfigurer) configurer).csrfTokenRepository(csrfTokenRepository());
        }

        // security context configuration
        if ((configurer = httpSecurity.getConfigurer(SecurityContextConfigurer.class)) != null) {
            ((SecurityContextConfigurer) configurer).securityContextRepository(securityContextRepository());
        }

        // session management configuration
        httpSecurity.removeConfigurer(SessionManagementConfigurer.class);

        // request cache configuration
        httpSecurity.setSharedObject(RequestCache.class, requestCache());

        super.init(web);
    }

    protected CsrfTokenRepository csrfTokenRepository() {
        return new LazyCsrfTokenRepository(new CookieCsrfTokenRepository());
    }

    protected SecurityContextRepository securityContextRepository() {
        return new NullSecurityContextRepository();
    }

    protected RequestCache requestCache() {
        return new CookieRequestCache();
    }

    protected AuthenticationFailureHandler authenticationFailureHandler() {
        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler();
        handler.setAllowSessionCreation(false);
        return handler;
    }

    static class SessionCreationCheckFilter implements Filter {
        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
            chain.doFilter(new SessionlessRequest((HttpServletRequest) request), response);
        }
    }

    static class SessionlessRequest extends HttpServletRequestWrapper {
        SessionlessRequest(HttpServletRequest request) {
            super(request);
        }

        @Override
        public HttpSession getSession(boolean create) {
            if (create) {
                sessionCreationException();
            }

            return super.getSession(create);
        }

        @Override
        public HttpSession getSession() {
            sessionCreationException();
            return null;
        }

        private RuntimeException sessionCreationException() {
            throw new RuntimeException("Trying to create a session in sessionless context");
        }
    }
}
