<template>
    <div>
        <div v-if="!$root.isAdmin" class="mt-5 d-flex align-items-center justify-content-center my-3">
            {{ $t("Only admins can manage users.") }}
        </div>
        <div v-else>
            <div class="add-btn">
                <button class="btn btn-primary me-2" type="button" @click="showAddDialog()">
                    <font-awesome-icon icon="plus" />
                    {{ $t("Add User") }}
                </button>
            </div>

            <div>
                <span
                    v-if="$root.userList.length === 0"
                    class="d-flex align-items-center justify-content-center my-3"
                >
                    {{ $t("No users found.") }}
                </span>

                <div
                    v-for="user in $root.userList"
                    :key="user.id"
                    class="item"
                    :class="{ inactive: !user.active }"
                >
                    <div class="left-part">
                        <div class="circle" :class="roleClass(user.role)"></div>
                        <div class="info">
                            <div class="title">{{ user.username }}</div>
                            <div class="role-badge">
                                <span class="badge" :class="roleBadgeClass(user.role)">
                                    {{ roleName(user.role) }}
                                </span>
                            </div>
                            <div class="status-text">
                                {{ user.active ? $t("Active") : $t("Inactive") }}
                            </div>
                        </div>
                    </div>

                    <div class="buttons">
                        <div class="btn-group" role="group">
                            <button class="btn btn-normal" @click="showEditDialog(user)">
                                <font-awesome-icon icon="pen" />
                                {{ $t("Edit") }}
                            </button>

                            <button
                                v-if="user.id !== currentUserID"
                                class="btn btn-danger"
                                @click="confirmDelete(user)"
                            >
                                <font-awesome-icon icon="trash" />
                                {{ $t("Delete") }}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Add/Edit User Dialog -->
        <div
            ref="userModal"
            class="modal fade"
            tabindex="-1"
        >
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            {{ isEditing ? $t("Edit User") : $t("Add User") }}
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Username") }}</label>
                            <input
                                v-model="formUser.username"
                                type="text"
                                class="form-control"
                                :disabled="isEditing"
                                required
                            />
                        </div>
                        <div class="mb-3">
                            <label class="form-label">
                                {{ $t("Password") }}
                                <span v-if="isEditing" class="text-muted">({{ $t("Leave blank to keep current") }})</span>
                            </label>
                            <input
                                v-model="formUser.password"
                                type="password"
                                class="form-control"
                                :required="!isEditing"
                            />
                        </div>
                        <div class="mb-3">
                            <label class="form-label">{{ $t("Role") }}</label>
                            <select v-model="formUser.role" class="form-select">
                                <option value="admin">{{ $t("Admin") }} - {{ $t("Full access, no limitations") }}</option>
                                <option value="developer">{{ $t("Developer") }} - {{ $t("Add and manage servers/services") }}</option>
                                <option value="readonly">{{ $t("Read-Only") }} - {{ $t("View dashboard and status pages only") }}</option>
                            </select>
                        </div>
                        <div v-if="isEditing" class="mb-3 form-check">
                            <input
                                v-model="formUser.active"
                                type="checkbox"
                                class="form-check-input"
                                :disabled="formUser.id === currentUserID"
                            />
                            <label class="form-check-label">{{ $t("Active") }}</label>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            {{ $t("Cancel") }}
                        </button>
                        <button type="button" class="btn btn-primary" @click="saveUser()">
                            {{ $t("Save") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Delete Confirmation Dialog -->
        <div
            ref="deleteModal"
            class="modal fade"
            tabindex="-1"
        >
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{{ $t("Delete User") }}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        {{ $t("Are you sure you want to delete this user?") }}
                        <strong>{{ deleteTarget?.username }}</strong>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                            {{ $t("Cancel") }}
                        </button>
                        <button type="button" class="btn btn-danger" @click="deleteUser()">
                            {{ $t("Delete") }}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import { Modal } from "bootstrap";

export default {
    data() {
        return {
            formUser: {
                username: "",
                password: "",
                role: "developer",
                active: true,
                id: null,
            },
            isEditing: false,
            deleteTarget: null,
            userModal: null,
            deleteModalInstance: null,
        };
    },

    computed: {
        currentUserID() {
            // Get the user ID from the socket
            return null; // We don't expose socket.userID to frontend, so we rely on server-side checks
        },
    },

    mounted() {
        this.loadUserList();
    },

    methods: {
        loadUserList() {
            this.$root.getSocket().emit("getUserList", (res) => {
                if (!res.ok) {
                    this.$root.toastError(res.msg);
                }
            });
        },

        roleName(role) {
            const names = {
                admin: this.$t("Admin"),
                developer: this.$t("Developer"),
                readonly: this.$t("Read-Only"),
            };
            return names[role] || role;
        },

        roleClass(role) {
            return "role-" + role;
        },

        roleBadgeClass(role) {
            const classes = {
                admin: "bg-danger",
                developer: "bg-primary",
                readonly: "bg-secondary",
            };
            return classes[role] || "bg-secondary";
        },

        showAddDialog() {
            this.isEditing = false;
            this.formUser = {
                username: "",
                password: "",
                role: "developer",
                active: true,
                id: null,
            };
            this.getModal().show();
        },

        showEditDialog(user) {
            this.isEditing = true;
            this.formUser = {
                id: user.id,
                username: user.username,
                password: "",
                role: user.role,
                active: !!user.active,
            };
            this.getModal().show();
        },

        getModal() {
            if (!this.userModal) {
                this.userModal = new Modal(this.$refs.userModal);
            }
            return this.userModal;
        },

        getDeleteModal() {
            if (!this.deleteModalInstance) {
                this.deleteModalInstance = new Modal(this.$refs.deleteModal);
            }
            return this.deleteModalInstance;
        },

        saveUser() {
            if (this.isEditing) {
                this.$root.getSocket().emit("editUser", this.formUser, (res) => {
                    this.$root.toastRes(res);
                    if (res.ok) {
                        this.getModal().hide();
                    }
                });
            } else {
                if (!this.formUser.username) {
                    this.$root.toastError("Username is required.");
                    return;
                }
                if (!this.formUser.password) {
                    this.$root.toastError("Password is required.");
                    return;
                }
                this.$root.getSocket().emit("addUser", this.formUser, (res) => {
                    this.$root.toastRes(res);
                    if (res.ok) {
                        this.getModal().hide();
                    }
                });
            }
        },

        confirmDelete(user) {
            this.deleteTarget = user;
            this.getDeleteModal().show();
        },

        deleteUser() {
            if (!this.deleteTarget) {
                return;
            }
            this.$root.getSocket().emit("deleteUser", this.deleteTarget.id, (res) => {
                this.$root.toastRes(res);
                if (res.ok) {
                    this.getDeleteModal().hide();
                }
            });
        },
    },
};
</script>

<style lang="scss" scoped>
@import "../../assets/vars.scss";

.add-btn {
    padding-top: 20px;
    padding-bottom: 20px;
}

.item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 15px;
    border-radius: 10px;
    margin-bottom: 5px;

    &:hover {
        background-color: $highlight-white;

        .dark & {
            background-color: $dark-header-bg;
        }
    }

    &.inactive {
        opacity: 0.5;
    }
}

.left-part {
    display: flex;
    align-items: center;
    gap: 12px;
}

.circle {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background-color: #6c757d;

    &.role-admin {
        background-color: #dc3545;
    }

    &.role-developer {
        background-color: #5cdd8b;
    }

    &.role-readonly {
        background-color: #6c757d;
    }
}

.info {
    .title {
        font-weight: bold;
        font-size: 16px;
    }

    .role-badge {
        margin-top: 2px;
    }

    .status-text {
        font-size: 13px;
        color: $secondary-text;
    }
}
</style>
