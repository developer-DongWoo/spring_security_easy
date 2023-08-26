package security.securityFrame.Auth.config;

import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import security.securityFrame.Auth.filter.JwtAuthenticationFilter;
import security.securityFrame.Auth.filter.JwtVerificationFilter;
import security.securityFrame.Auth.handler.MemberAccessDeniedHandler;
import security.securityFrame.Auth.handler.MemberAuthenticationEntryPoint;
import security.securityFrame.Auth.handler.MemberAuthenticationFailureHandler;
import security.securityFrame.Auth.handler.MemberAuthenticationSuccessHandler;
import security.securityFrame.Auth.oauth2.OAuth2MemberSuccessHandler;
import security.securityFrame.Auth.provider.TokenProvider;
import security.securityFrame.Auth.role.RoleService;
import security.securityFrame.Auth.utils.MemberAuthorityUtil;
import security.securityFrame.member.service.MemberService;

import java.util.Arrays;
import java.util.stream.Collectors;

import static security.securityFrame.Auth.utils.TokenPrefix.REFRESH;
import static org.springframework.http.HttpMethod.*;
import static security.securityFrame.Auth.config.AllowedOrigins.*;
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final TokenProvider tokenProvider;
    private final MemberAuthorityUtil authorityUtil;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        ApplicationContext context = getApplicationContext();

        httpSecurity
                .headers().frameOptions().sameOrigin()

                .and()
                .csrf().disable()
                .cors(Customizer.withDefaults())
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .formLogin().disable()
                .httpBasic().disable()

                .exceptionHandling()
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint())
                .accessDeniedHandler(new MemberAccessDeniedHandler())

                .and()
                .apply(new CustomFilterConfigurer(context.getBean(MemberService.class)))

                .and()
                .logout()
                .logoutUrl("/logout")
                .addLogoutHandler(((request, response, authentication) -> {
                    response.setHeader("Set-Cookie", REFRESH.getType() +
                            "=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0;"); // HttpOnly 옵션을 사용함으로써, 자바스크립트를 이용한 접근이 불가능해짐
                    response.setHeader("Access-Control-Allow-Origin", COOKIE_ALLOW_ORIGIN.getOrigin());
                }))
                .logoutSuccessUrl(COOKIE_ALLOW_ORIGIN.getOrigin() + "/")

                .and()
                .authorizeRequests(this::configureAuthorization)
                .oauth2Login(oAuth2 -> oAuth2
                        .successHandler(new OAuth2MemberSuccessHandler(
                                context.getBean(MemberService.class), context.getBean(RoleService.class), tokenProvider)
                        )
                );
    }

    private void configureAuthorization
            (ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorize) {
        String USER = authorityUtil.getUSER();
        String PARTNER = authorityUtil.getPARTNER();

        authorize
                // PARTNER 권한

                // USER 권한

                .mvcMatchers("/").permitAll();
    }

    // JwtAuthenticationFilter 구성하는 클래스
    @AllArgsConstructor
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {
        private final MemberService memberService;

        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager =
                    builder.getSharedObject(AuthenticationManager.class);

            JwtAuthenticationFilter jwtAuthenticationFilter =
                    new JwtAuthenticationFilter(authenticationManager);
            jwtAuthenticationFilter.setFilterProcessesUrl("/auth/login");
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler(tokenProvider));
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());

            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(tokenProvider, authorityUtil, memberService);

            // Spring Security Filter Chain에 추가
            builder.addFilter(jwtAuthenticationFilter)
                    .addFilterAfter(jwtVerificationFilter, OAuth2LoginAuthenticationFilter.class)
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }

    // 구체적인 CORS 정책 설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(
                Arrays.stream(AllowedOrigins.values())
                        .map(AllowedOrigins::getOrigin)
                        .distinct()
                        .collect(Collectors.toList())
        );

        configuration.setAllowCredentials(true);
        configuration.setMaxAge(2000L);
        //Todo 헤더에 들어갈 key값을 지정할 수 있으며, 이외의 값이 들어있으면 차단
        configuration.setAllowedHeaders(Arrays.asList("*"));
//        configuration.setAllowedHeaders(Arrays.asList("Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization", "Refresh", "Set-Cookie"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Refresh"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
