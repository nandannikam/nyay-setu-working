package com.nyaysetu.backend.config;

import com.nyaysetu.backend.filter.JwtAuthFilter;
import com.nyaysetu.backend.filter.RateLimitFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final RateLimitFilter rateLimitFilter;

    @Value("${cors.allowed.origins}")
    private String allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> origins = Arrays.asList(allowedOrigins.split(","));
        configuration.setAllowedOrigins(origins);
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter) throws Exception {

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth

                        // ── Public endpoints ──────────────────────────────────────────────
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/forgot-password",
                                "/api/auth/verify-reset-token",
                                "/api/auth/reset-password",
                                "/api/auth/face/login",
                                "/api/auth/ping",
                                "/api/auth/test",
                                "/api/health",
                                "/api/police/health"
                        ).permitAll()

                        // ── WebSocket endpoints ───────────────────────────────────────────
                        .requestMatchers("/api/ws/**").permitAll()

                        // ── AI endpoints (open for now; restrict if misuse detected) ──────
                        .requestMatchers(
                                "/ai/summarize",
                                "/ai/chat",
                                "/ai/chat/ollama",
                                "/ai/constitution/qa",
                                "/ai/ollama/status",
                                "/ai/ollama/models",
                                "/api/brain/analyze-case",
                                "/api/brain/suggest-documents"
                        ).permitAll()

                        // ── Auth-only: any authenticated user ─────────────────────────────
                        .requestMatchers(
                                "/api/auth/face/enroll",
                                "/api/auth/face/disable",
                                "/api/auth/face/status",
                                "/api/face/enroll",
                                "/api/face/verify",
                                "/api/face/status",
                                "/api/face/remove",
                                "/profile/**"
                        ).authenticated()

                        // ── Brain / AI (authenticated) ────────────────────────────────────
                        .requestMatchers("/api/brain/**").authenticated()

                        // ── Judge-only endpoints ──────────────────────────────────────────
                        .requestMatchers(
                                "/api/judge/**",
                                "/api/hearings/schedule",
                                "/api/hearings/*/complete",
                                "/api/hearings/*/outcome",
                                "/api/hearings/*/participants",
                                "/api/orders",
                                "/api/orders/*",
                                "/api/orders/my-orders",
                                "/api/cases/*/assign-judge",
                                "/api/cases/*/take-cognizance",
                                "/api/cases/*/order-notice",
                                "/api/cases/transition/*/take-cognizance",
                                "/api/cases/transition/*/advance-stage"
                        ).hasAnyRole("JUDGE", "SUPER_JUDGE", "ADMIN")

                        // ── Police-only endpoints ─────────────────────────────────────────
                        .requestMatchers(
                                "/api/police/summons/**",
                                "/api/police/fir/**",
                                "/api/police/investigation/**",
                                "/api/police/stats"
                        ).hasAnyRole("POLICE", "ADMIN")

                        // ── Lawyer-only endpoints ─────────────────────────────────────────
                        .requestMatchers(
                                "/api/lawyer/**",
                                "/api/cases/transition/*/save-draft"
                        ).hasAnyRole("LAWYER", "ADMIN")

                        // ── Litigant endpoints ────────────────────────────────────────────
                        .requestMatchers(
                                "/api/client/fir/**",
                                "/api/cases/transition/*/approve-draft",
                                "/api/cases/transition/*/reject-draft"
                        ).hasAnyRole("LITIGANT", "ADMIN")

                        // ── Admin/oversight-only endpoints ────────────────────────────────
                        .requestMatchers(
                                "/api/cases/pending-assignment",
                                "/api/cases/judge-workload",
                                "/verify/admin/**",
                                "/api/audit/log"
                        ).hasAnyRole("ADMIN", "SUPER_JUDGE", "TECH_ADMIN")

                        // ── Summons & transition (police + judge + admin) ──────────────────
                        .requestMatchers(
                                "/api/cases/*/update-summons",
                                "/api/cases/transition/*/summons-served"
                        ).hasAnyRole("POLICE", "JUDGE", "SUPER_JUDGE", "ADMIN")

                        // ── Everything else requires authentication ────────────────────────
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
