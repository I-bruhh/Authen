from django.db import models
from django.utils import timezone

# Create your models here.
    
class Timestamp(models.Model):
    creationDate = models.DateTimeField(auto_now_add=True) #auto_now_add will add the timestamp automatically when created
    updateDate = models.DateTimeField(auto_now=True) #auto_now will add the timestamp automatically when updated
    deleteDate = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True

    def setDeletedDate(self):
        self.deleteDate = timezone.now()
        self.save()

    def getCreationDate(self):
        return self.creationDate
    
    def getUpdateDate(self):
        return self.updateDate
    
    def getDeletedDate(self):
        return self.deleteDate