package com.rikkei.identity.service;

import com.rikkei.identity.config.AppProperties;
import com.rikkei.identity.entity.RefreshToken;
import com.rikkei.identity.entity.User;
import com.rikkei.identity.repository.RefreshTokenRepository;
import com.rikkei.identity.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final long refreshTokenExpiration;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               UserRepository userRepository,
                               AppProperties appProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.refreshTokenExpiration = appProperties.getRefreshTokenExpiration();
    }

    /**
     * Creates a new refresh token for the given user.
     * Deletes any previously issued refresh token for that user first.
     *
     * @param userId the user's ID
     * @return the newly created RefreshToken entity
     */
    @Transactional
    public RefreshToken createRefreshToken(String userId) {
        // Remove any existing refresh token for this user
        refreshTokenRepository.deleteByUser_Id(userId);

        User user = userRepository.findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found: " + userId));

        RefreshToken refreshToken = new RefreshToken(
            UUID.randomUUID().toString(),
            Instant.now().plusMillis(refreshTokenExpiration),
            user
        );

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Verifies that the given refresh token has not expired.
     *
     * @param token the RefreshToken entity to verify
     * @return the same token if still valid
     * @throws RuntimeException if the token has expired
     */
    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token expired. Please log in again.");
        }
        return token;
    }
}
