package com.lgellu.JwtSecurity.repository;

import com.lgellu.JwtSecurity.model.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Query("Delete from RefreshToken r where r.username = :username")
    void deleteByUsername(String username);

    @Modifying
    @Query("DELETE FROM RefreshToken r WHERE r.expiresAt < :now OR r.revoked = true")
    void purgeInvalidTokens(@Param("now") Instant now);
}
