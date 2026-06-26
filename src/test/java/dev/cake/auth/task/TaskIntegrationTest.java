package dev.cake.auth.task;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.common.exception.EmailNotVerifiedException;
import dev.cake.auth.common.exception.ResourceNotFoundException;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Transactional
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class TaskIntegrationTest extends AbstractIntegrationTest {

    @Autowired
    TaskService taskService;
    @Autowired
    TaskRepository taskRepository;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void when_valid_task_creation_input_given_creates_task_and_returns_task_response() {
        var user = getPersistedUser(true);
        var createTaskRequest = new CreateTaskRequest("clear garden",
                "eliminate crop bags",
                Instant.now().plus(Duration.ofHours(1)));

        var taskResponse = taskService.create(user.getPublicId(), createTaskRequest);
        var optTask = taskRepository.findByPublicIdAndUser(taskResponse.id(), user);

        assertThat(optTask).isPresent();
        assertThat(optTask.get().getName()).isEqualTo(createTaskRequest.name());
        assertThat(optTask.get().getDescription()).isEqualTo(createTaskRequest.description());
        assertThat(optTask.get().getDeadline()).isAfter(Instant.now());
        assertThat(optTask.get().getStatus()).isEqualTo(TaskStatus.TODO);
    }

    @Test
    void when_user_not_found_throws_resource_not_found_exception() {
        var createTaskRequest = new CreateTaskRequest("clear garden",
                "eliminate crop bags",
                Instant.now().plus(Duration.ofHours(1)));
        UUID randomUuid = UUID.randomUUID();
        assertThatThrownBy(() -> taskService.create(randomUuid, createTaskRequest))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("%s '%s' not found", "User", randomUuid.toString());
    }

    @Test
    void when_user_is_not_verified_throws_email_not_verified_exception() {
        var user = getPersistedUser(false);
        var createTaskRequest = new CreateTaskRequest("clear garden",
                "eliminate crop bags",
                Instant.now().plus(Duration.ofHours(1)));
        assertThatThrownBy(() -> taskService.create(user.getPublicId(), createTaskRequest))
                .isInstanceOf(EmailNotVerifiedException.class);
    }

    private @NonNull User getPersistedUser(boolean verified) {
        return userRepository.saveAndFlush(User.builder()
                .username("cakeslayer")
                .email("cakeslayer@dev.com")
                .emailVerified(verified)
                .passwordHash(passwordEncoder.encode("password"))
                .build());
    }

}
