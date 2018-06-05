from canari.maltego.message import *

__author__ = 'Shaddy Garg'
__copyright__ = 'Copyright 2018, nettacker-transform Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = 'Shaddy Garg'
__email__ = 'shaddygarg1@gmail.com'
__status__ = 'Development'

__all__ = [
    'Nettacker-transformEntity',
    'MyNettacker-transformEntity'
]


class Nettacker-transformEntity(Entity):
    """This is the base entity used to optionally define the namespace for all your other entities. The namespace is the
    string preceding the name of your entity separated by a dot (i.e. 'foo' in 'foo.BarTransform'). If _namespace_ is
    not defined as a class variable, then the namespace will be generated based on the name of your Canari package. For
    example, if your project's name is 'sniffmypackets' then the namespace will also be 'sniffmypackets'.
    """
    pass


class MyNettacker-transformEntity(Nettacker-transformEntity):
    """This is an example of a custom entity that you would design. Here we can specify a custom namespace if we want to
    further segment our entities into separate namespaces by specifying the '_namespace_' class variable. (i.e.
    'socialmedia.twitter.Tweet', 'socialmedia.myspace.Post', etc.). Or maybe you'd like to specify a custom fully
    qualified type name by defining the '_type_' class variable. By default the type is set to the name of your Canari
    package dot the name of this entity class. Most importantly, you're probably wondering how to specify custom entity
    fields. Take a look below for examples of the different built-in field types provided from the
    'canari.maltego.message' package.
    """
    str = StringEntityField('type.str', display_name='Foo String')
    int = IntegerEntityField('type.int', display_name='Foo Integer')
    float = FloatEntityField('type.float', display_name='Foo Float')
    bool = BooleanEntityField('type.bool', display_name='Foo Boolean')
    enum = EnumEntityField('type.enum', choices=[2, 1, 0], display_name='Foo Enum')
    date = DateEntityField('type.date', display_name='Foo Date')
    datetime = DateTimeEntityField('type.datetime', display_name='Foo Datetime')
    timespan = TimeSpanEntityField('type.timespan', display_name='Foo Timespan')
    color = ColorEntityField('type.color', display_name='Foo Color')