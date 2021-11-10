package configuration;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

public class AuthenticationManagerBuilderImportSelector implements ImportSelector, BeanFactoryAware {
    private BeanFactory beanFactory;

    @Override
    public String[] selectImports(AnnotationMetadata importingClassMetadata) {
        try {
            beanFactory.getBean(AuthenticationManagerBuilder.class);
        } catch (BeansException e) {
            return new String[] {
                    AuthenticationConfiguration.class.getName()
            };
        }
        return new String[0];
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }
}
