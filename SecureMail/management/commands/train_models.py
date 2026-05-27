from django.core.management.base import BaseCommand
from SecureMail.ml.train import train_models

class Command(BaseCommand):
    help = 'Trains and saves the local XGBoost models for phishing detection and categorization.'

    def handle(self, *args, **options):
        self.stdout.write("Starting ML model training pipeline...")
        try:
            train_models()
            self.stdout.write(self.style.SUCCESS("Models trained and saved successfully."))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Training failed: {str(e)}"))
