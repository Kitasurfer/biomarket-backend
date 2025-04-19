package de.aittr.bio_marketplace.security.config;

import de.aittr.bio_marketplace.security.filter.JwtAuthenticationFilter;
import de.aittr.bio_marketplace.security.service.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, proxyTargetClass = true)
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    private final String ADMIN_ROLE = "ADMIN";
    private final String USER_ROLE = "USER";
    private final String SELLER_ROLE = "SELLER";

    public SecurityConfig(CustomUserDetailsService userDetailsService,
                          JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    //настройки CORS

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        //если фронт на другом порту поменяй порт/длмен
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        config.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //применяем эти настройки ко всем эндпоинтам
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                //Вкл CORS конфиг.
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(authorizeRequests -> authorizeRequests

                        // Auth controller
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register", "/auth/logout").permitAll()
                        .requestMatchers(HttpMethod.GET, "/auth/refresh").permitAll()

                                // Confirm controller
                                .requestMatchers(HttpMethod.GET, "/confirm/**").permitAll()
                                .requestMatchers(HttpMethod.GET, "/reset-password").permitAll()

                        // Product controller
                        .requestMatchers(HttpMethod.POST, "/products").hasAnyRole(USER_ROLE, SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/products").permitAll()
                        .requestMatchers(HttpMethod.GET, "/products/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/products").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/products/**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/products/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/products/deactivate/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/products/**").hasRole(ADMIN_ROLE)

                        // Category controller
                        .requestMatchers(HttpMethod.POST, "/categories").hasAnyRole(USER_ROLE, SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/categories").permitAll()
                        .requestMatchers(HttpMethod.GET, "/categories/**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/categories/**").hasRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/categories/**").hasRole(ADMIN_ROLE)

                        // Wishlist controller
                        .requestMatchers(HttpMethod.POST, "/wishlist/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/wishlist").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/wishlist").hasAnyRole(USER_ROLE, ADMIN_ROLE)

                        // Cart controller
                        .requestMatchers(HttpMethod.POST, "/cart/add").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/cart").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/cart/update").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/cart/remove/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/cart/clear").hasAnyRole(USER_ROLE, ADMIN_ROLE)

                        // User controller
                        .requestMatchers(HttpMethod.GET, "/users").hasAnyRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/{id}").hasAnyRole(ADMIN_ROLE, USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/total-cost/**").hasAnyRole(USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/all-products-by-user-id/**").hasAnyRole(USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/all-sellers-by-user-id/**").hasAnyRole(USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/product-average-price/**").hasAnyRole(USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/users/**").hasAnyRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/users").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/users/change-password/**").hasAnyRole(ADMIN_ROLE, USER_ROLE, SELLER_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/users//{userId}/product/{productId}").hasAnyRole(ADMIN_ROLE, SELLER_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/users/**").hasAnyRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/users/remove-user/**").hasAnyRole(ADMIN_ROLE, USER_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/users/clear-cart/**").hasAnyRole(ADMIN_ROLE, USER_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/users/**").hasAnyRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.POST, "/users/request-reset", "/users/reset").permitAll()


                        // Order controller
                        .requestMatchers(HttpMethod.POST, "/orders").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/orders/user").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.GET, "/orders/seller/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/orders").hasRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/orders/user/deactivate/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/orders/seller/deactivate/**").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/orders/**").hasRole(ADMIN_ROLE)

                        // TODO: change later .requestMatchers(HttpMethod.GET, "/orders/seller/**").permitAll()

                        // Seller controller
                        .requestMatchers(HttpMethod.GET, "/sellers").permitAll()
                        .requestMatchers(HttpMethod.GET, "/sellers/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/sellers/**").hasAnyRole(ADMIN_ROLE, USER_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/sellers").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/sellers/**").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/sellers/**").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)

                        // Review controller
                        .requestMatchers(HttpMethod.GET, "/reviews").permitAll()
                        .requestMatchers(HttpMethod.GET, "/reviews/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/reviews/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/reviews").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/reviews/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/reviews").hasRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/reviews/**").hasAnyRole(ADMIN_ROLE, USER_ROLE)


                        // Address сontroller
                        .requestMatchers(HttpMethod.GET, "/address").hasRole(USER_ROLE)
                        .requestMatchers(HttpMethod.GET, "/address/**").hasRole(USER_ROLE)
                        .requestMatchers(HttpMethod.POST, "/address/**").hasAnyRole(USER_ROLE, ADMIN_ROLE, SELLER_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/address").hasAnyRole(USER_ROLE, SELLER_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/address").hasRole(ADMIN_ROLE)
                        .requestMatchers(HttpMethod.DELETE, "/address/**").hasAnyRole(USER_ROLE, ADMIN_ROLE)

                        // File controller
                        .requestMatchers(HttpMethod.POST, "/files/product_images").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)
                        .requestMatchers(HttpMethod.PUT, "/files/product_images").hasAnyRole(SELLER_ROLE, ADMIN_ROLE)

                        .requestMatchers("/v3/api-docs",
                                "/v3/api-docs/**",
                                "/swagger-ui/",
                                "/swagger-ui.html",
                                "/swagger-ui/index.html",
                                "/swagger-ui/**").permitAll()

                        .anyRequest().authenticated()
                )

                .sessionManagement(x -> x.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //добавляем наш фильтр
                .addFilterBefore(jwtAuthenticationFilter,
                        org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)

                .authenticationProvider(authenticationProvider())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }
}
