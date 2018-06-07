from canari.maltego.entities import Person, Phrase
from canari.maltego.transform import Transform
from canari.framework import EnableDebugWindow

__author__ = 'Shaddy Garg'
__copyright__ = 'Copyright 2018, nettacker_transforms Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = 'Shaddy Garg'
__email__ = 'shaddygarg1@gmail.com'
__status__ = 'Development'


@EnableDebugWindow
class HelloWorld(Transform):
    """This transform returns a set of phrases with various salutations to a Person's name."""

    # The transform input entity type.
    input_type = Person

    def do_transform(self, request, response, config):
        # Since we know what the input_type of this transform is, we can directly access static fields. Alternatively,
        # dynamic field values can still be accessed by querying the entity.fields property.
        person = request.entity
        response += Phrase('Hello %s!' % person.value)
        response += Phrase('This way Mr(s). %s!' % person.lastname)
        response += Phrase('Hi %s!' % person.firstnames)
        return response

    def on_terminate(self):
        """
        This method gets called when transform execution is prematurely terminated. It is only applicable for local
        transforms.
        """
        pass