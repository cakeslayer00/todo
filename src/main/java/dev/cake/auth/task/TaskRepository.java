package dev.cake.auth.task;

import dev.cake.auth.identity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

interface TaskRepository extends JpaRepository<Task, Long> {

    List<Task> findAllByUser(User user);

    List<Task> findAllByUserAndStatus(User user, TaskStatus status);

    Optional<Task> findByPublicIdAndUser(UUID publicId, User user);

}
