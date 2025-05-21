import customtkinter as ctk

def load_view(parent_frame, update_status_callback):
    for widget in parent_frame.winfo_children():
        widget.destroy()

    status_var = ctk.StringVar(value="Ready")

    def set_status(message):
        status_var.set(message)
        update_status_callback(message)

    def run_security_audit():
        set_status("🔍 Running Security Audit...")
        audit_output.configure(state="normal")
        audit_output.delete("1.0", "end")

        # Simulate checks (replace with real logic later)
        checks = [
            "Check 1: 🔒 Firewall status - OK",
            "Check 2: 🛡️ Defender enabled - OK",
            "Check 3: 🧱 BitLocker - NOT ENABLED",
            "Check 4: 🪪 User account control - ENABLED",
            "Check 5: 🔍 Secure Boot - ENABLED"
        ]

        for line in checks:
            audit_output.insert("end", line + "\n")

        audit_output.configure(state="disabled")
        set_status("✅ Security Audit Complete")

    # Heading
    ctk.CTkLabel(parent_frame, text="🛡️ Security Audit", font=("Consolas", 18)).pack(pady=10)

    # Run button
    ctk.CTkButton(parent_frame, text="Run Security Audit", command=run_security_audit).pack(pady=(0, 10))

    # Output box
    audit_output = ctk.CTkTextbox(parent_frame, height=250, wrap="word")
    audit_output.pack(padx=10, pady=10, fill="both")
    audit_output.insert("end", "📝 Audit results will appear here...")
    audit_output.configure(state="disabled")

    # Status bar
    ctk.CTkLabel(parent_frame, textvariable=status_var, anchor="w", wraplength=800).pack(padx=10, pady=5, fill="x")
