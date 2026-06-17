package dev.cake.auth.identity;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.sociallogin.FederatedUser;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class IdentityProvisioningServiceIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    IdentityProvisioningService provisioningService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    IdentityRepository identityRepository;

    @Test
    void when_identity_already_linked_returns_existing_user_without_creating_rows() {
        var user = userRepository.saveAndFlush(User.builder()
                .email("linked@example.com")
                .emailVerified(true)
                .build());
        identityRepository.saveAndFlush(Identity.builder()
                .user(user)
                .provider(AuthProvider.GOOGLE)
                .providerSubject("google-sub-1")
                .build());

        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GOOGLE, "google-sub-1", "linked@example.com", true));

        assertThat(provisioned.getPublicId()).isEqualTo(user.getPublicId());
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(identityRepository.count()).isEqualTo(1);
    }

    @Test
    void when_no_link_but_verified_email_exists_links_identity_to_existing_user() {
        var existing = userRepository.saveAndFlush(User.builder()
                .email("verified@example.com")
                .emailVerified(true)
                .build());

        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GITHUB, "github-sub-1", "verified@example.com", true));

        assertThat(provisioned.getPublicId()).isEqualTo(existing.getPublicId());
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(identityRepository.findUserByProviderAndProviderSubject(
                AuthProvider.GITHUB, "github-sub-1"))
                .get()
                .extracting(User::getPublicId)
                .isEqualTo(existing.getPublicId());
    }

    @Test
    void when_no_link_and_no_existing_email_creates_user_and_identity() {
        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GOOGLE, "google-sub-2", "fresh@example.com", true));

        assertThat(provisioned.getId()).isNotNull();
        assertThat(provisioned.getEmail()).isEqualTo("fresh@example.com");
        assertThat(provisioned.isEmailVerified()).isTrue();
        assertThat(userRepository.count()).isEqualTo(1);
        assertThat(identityRepository.findUserByProviderAndProviderSubject(
                AuthProvider.GOOGLE, "google-sub-2"))
                .get()
                .extracting(User::getPublicId)
                .isEqualTo(provisioned.getPublicId());
    }

    @Test
    void when_existing_email_is_unverified_verified_federated_login_claims_the_account() {
        var existing = userRepository.saveAndFlush(User.builder()
                .email("unverified@example.com")
                .emailVerified(false)
                .passwordHash("$2a$10$preexistingUntrustedHash")
                .build());

        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GITHUB, "github-sub-2", "unverified@example.com", true));

        assertThat(provisioned.getPublicId()).isEqualTo(existing.getPublicId());
        assertThat(userRepository.count()).isEqualTo(1);

        assertThat(provisioned.isEmailVerified()).isTrue();
        assertThat(provisioned.getPasswordHash()).isNull();
        assertThat(identityRepository.findUserByProviderAndProviderSubject(
                AuthProvider.GITHUB, "github-sub-2"))
                .get()
                .extracting(User::getPublicId)
                .isEqualTo(existing.getPublicId());
    }

    @Test
    void when_existing_email_is_unverified_and_federated_email_is_unverified_account_is_not_claimed() {
        var existing = userRepository.saveAndFlush(User.builder()
                .email("unverified@example.com")
                .emailVerified(false)
                .passwordHash("$2a$10$preexistingUntrustedHash")
                .build());

        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GITHUB, "github-sub-4", "unverified@example.com", false));

        assertThat(provisioned.getPublicId()).isEqualTo(existing.getPublicId());
        assertThat(provisioned.isEmailVerified()).isFalse();
        assertThat(provisioned.getPasswordHash()).isEqualTo("$2a$10$preexistingUntrustedHash");
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    void propagates_email_verified_flag_from_federated_user_onto_created_user() {
        var provisioned = provisioningService.provision(new FederatedUser(
                AuthProvider.GITHUB, "github-sub-3", "notverified@example.com", false));

        assertThat(provisioned.isEmailVerified()).isFalse();
    }

}
