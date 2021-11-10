package configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;

@Import(AuthenticationManagerBuilderImportSelector.class)
@Configuration(proxyBeanMethods = false)
public class SessionlessHttpSecurityConfiguration {
    private final static String HTTPSECURITY_BEAN_NAME = "sessionless.httpSecurity";
    private ObjectPostProcessor<Object> objectPostProcessor;

    private AuthenticationManager authenticationManager;

    private AuthenticationConfiguration authenticationConfiguration;

    private ApplicationContext context;

    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    void setObjectPostProcessor(ObjectPostProcessor<Object> objectPostProcessor) {
        this.objectPostProcessor = objectPostProcessor;
    }

    @Autowired(required = false)
    void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Autowired
    void setAuthenticationConfiguration(AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }

    @Autowired
    void setApplicationContext(ApplicationContext context) {
        this.context = context;
    }

    @Autowired
    void setAuthenticationManagerBuilder(AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @Bean(HTTPSECURITY_BEAN_NAME)
    @Scope("prototype")
    HttpSecurity httpSecurity() throws Exception {
        AuthenticationManagerBuilder authenticationBuilder = this.authenticationManagerBuilder;
        authenticationBuilder.parentAuthenticationManager(authenticationManager());
        HttpSecurity http = new HttpSecurity(this.objectPostProcessor, authenticationBuilder, createSharedObjects());
        // @formatter:off
        http
                .csrf(withDefaults())
                .addFilter(new WebAsyncManagerIntegrationFilter())
                .exceptionHandling(withDefaults())
                .headers(withDefaults())
                .sessionManagement(withDefaults())
                .securityContext(withDefaults())
                .requestCache(withDefaults())
                .anonymous(withDefaults())
                .servletApi(withDefaults())
                .apply(new DefaultLoginPageConfigurer<>());
        http.logout(withDefaults());
        // @formatter:on
        return http;
    }

    private AuthenticationManager authenticationManager() throws Exception {
        return (this.authenticationManager != null) ? this.authenticationManager
                : this.authenticationConfiguration.getAuthenticationManager();
    }

    private Map<Class<?>, Object> createSharedObjects() {
        Map<Class<?>, Object> sharedObjects = new HashMap<>();
        sharedObjects.put(ApplicationContext.class, this.context);
        return sharedObjects;
    }
}
