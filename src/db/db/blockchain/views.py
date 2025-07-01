from django.http import HttpRequest, HttpResponse

from .models import Commitment


def register_new_commitment(commitment: str):
    if Commitment.objects.filter(commitment=commitment).exists():
        return HttpResponse(status=409)
    new_hash = Commitment.make_hash(commitment)
    Commitment.objects.create(commitment=commitment, hash=new_hash)
    return HttpResponse(status=201)


def is_valid(commitment: str):
    if Commitment.objects.filter(commitment=commitment).exists():
        return HttpResponse(status=200)
    else:
        return HttpResponse(status=404)


def view(request: HttpRequest, commitment: str):
    if request.method == "GET":
        return is_valid(commitment)
    elif request.method == "PUT":
        return register_new_commitment(commitment)
    else:
        return HttpResponse(status=405)
