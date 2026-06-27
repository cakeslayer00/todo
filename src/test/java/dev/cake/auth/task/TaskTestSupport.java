package dev.cake.auth.task;

import dev.cake.auth.common.AbstractIntegrationTest;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import static dev.cake.auth.task.TaskFixtures.DEADLINE;
import static dev.cake.auth.task.TaskFixtures.DESCRIPTION;
import static dev.cake.auth.task.TaskFixtures.NAME;

abstract class TaskTestSupport extends AbstractIntegrationTest {

    @Autowired
    protected UserRepository userRepository;
    @Autowired
    protected TaskRepository taskRepository;
    @Autowired
    protected PasswordEncoder passwordEncoder;

    protected @NonNull User persistUser(boolean verified) {
        return persistUser("cakeslayer", "cakeslayer@dev.com", verified);
    }

    protected @NonNull User persistUser(String username, String email, boolean verified) {
        return userRepository.saveAndFlush(User.builder()
                .username(username)
                .email(email)
                .emailVerified(verified)
                .passwordHash(passwordEncoder.encode("password"))
                .build());
    }

    protected @NonNull Task persistTask(User user) {
        return persistTask(user, TaskStatus.TODO);
    }

    protected @NonNull Task persistTask(User user, TaskStatus status) {
        return taskRepository.saveAndFlush(Task.builder()
                .name(NAME)
                .description(DESCRIPTION)
                .user(user)
                .status(status)
                .deadline(DEADLINE)
                .build());
    }
}
