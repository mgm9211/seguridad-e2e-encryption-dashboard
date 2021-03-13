from django.shortcuts import render

# Create your views here.
def index(request):
    context = {}

    context['username'] = request.session.get('username')
    return render(request, "dashboard.html", context)