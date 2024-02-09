from django.db import migrations

def add_role_data(apps, schema_editor):
    Role = apps.get_model('user', 'Role')
    Role.objects.create(role_id=1, role_name="admin")
    Role.objects.create(role_id=2, role_name="user")
    

class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),  # Replace with the name of your initial migration
    ]

    operations = [
        migrations.RunPython(add_role_data),
    ]