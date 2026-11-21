package com.example.prism

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PasswordFormTest {
    @Test fun valid_form_has_no_error() = assertNull(passwordFormError("old123", "new123", "new123"))
    @Test fun empty_current_is_refused() = assertEquals("Enter your current password", passwordFormError("", "new123", "new123"))
    @Test fun short_new_password_is_refused() = assertEquals("New password must be at least 6 characters", passwordFormError("old123", "abc", "abc"))
    @Test fun same_password_is_refused() = assertEquals("New password must be different from the current one", passwordFormError("same12", "same12", "same12"))
    @Test fun adminForm() {
        assertNull(adminPasswordError("secret1", "secret1"))
        assertEquals("Password must be at least 6 characters", adminPasswordError("abc", "abc"))
        assertEquals("The two passwords do not match", adminPasswordError("secret1", "secret2"))
    }

    @Test fun mismatch_is_refused() = assertEquals("The new passwords do not match", passwordFormError("old123", "new123", "new124"))
}
