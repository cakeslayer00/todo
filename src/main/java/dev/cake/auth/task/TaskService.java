package dev.cake.auth.task;

import dev.cake.auth.common.exception.EmailNotVerifiedException;
import dev.cake.auth.common.exception.ResourceNotFoundException;
import dev.cake.auth.identity.User;
import dev.cake.auth.identity.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
class TaskService {

    private final TaskRepository taskRepository;
    private final UserRepository userRepository;

    @Transactional
    TaskResponse create(UUID ownerPublicId, CreateTaskRequest request) {
        var owner = requireVerifiedUser(ownerPublicId);

        var task = Task.builder()
                .name(request.name())
                .description(request.description())
                .user(owner)
                .status(TaskStatus.TODO)
                .deadline(request.deadline())
                .build();

        taskRepository.saveAndFlush(task);
        log.info("Task '{}' created for user '{}'", task.getPublicId(), ownerPublicId);
        return TaskResponse.from(task);
    }

    @Transactional(readOnly = true)
    List<TaskResponse> list(UUID ownerPublicId, TaskStatus status) {
        var owner = requireVerifiedUser(ownerPublicId);

        var tasks = status == null
                ? taskRepository.findAllByUser(owner)
                : taskRepository.findAllByUserAndStatus(owner, status);

        return tasks.stream().map(TaskResponse::from).toList();
    }

    @Transactional(readOnly = true)
    TaskResponse get(UUID ownerPublicId, UUID taskPublicId) {
        var owner = requireVerifiedUser(ownerPublicId);
        return TaskResponse.from(requireTask(taskPublicId, owner));
    }

    @Transactional
    TaskResponse update(UUID ownerPublicId, UUID taskPublicId, UpdateTaskRequest request) {
        var owner = requireVerifiedUser(ownerPublicId);
        var task = requireTask(taskPublicId, owner);

        task.setName(request.name());
        task.setDescription(request.description());
        task.setStatus(request.status());
        task.setDeadline(request.deadline());

        log.info("Task '{}' updated for user '{}'", taskPublicId, ownerPublicId);
        return TaskResponse.from(task);
    }

    @Transactional
    void delete(UUID ownerPublicId, UUID taskPublicId) {
        var owner = requireVerifiedUser(ownerPublicId);
        taskRepository.delete(requireTask(taskPublicId, owner));
        log.info("Task '{}' deleted for user '{}'", taskPublicId, ownerPublicId);
    }

    private User requireVerifiedUser(UUID publicId) {
        var user = requireUser(publicId);
        if (!user.isEmailVerified()) {
            throw new EmailNotVerifiedException();
        }
        return user;
    }

    private User requireUser(UUID publicId) {
        return userRepository.findByPublicId(publicId)
                .orElseThrow(() -> new ResourceNotFoundException("User", publicId.toString()));
    }

    private Task requireTask(UUID taskPublicId, User owner) {
        return taskRepository.findByPublicIdAndUser(taskPublicId, owner)
                .orElseThrow(() -> new ResourceNotFoundException("Task", taskPublicId.toString()));
    }

}
