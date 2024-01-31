from django.core.mail import EmailMessage


def send_email(contact: str, subject: str, message: str, host: str, recipients: list[str], bcc_recipients: list[str] = None):
    if bcc_recipients is None:
        bcc_recipients = []  # Initialize bcc_recipients as an empty list if not provided

    email = EmailMessage(
        {subject},
        f"From:\t{contact}\nMessage:\t{message}",
        host,
        recipients,
        bcc=bcc_recipients,  # Use the bcc parameter to specify Bcc recipients
    )
    email.send(fail_silently=False)
    return