Quick Start Guide
=================

This guide will get you started with PySpectre in under 5 minutes.


Installation
------------

Install PySpectre using pip:

.. code-block:: bash

   pip install pyspectre

This will also install the Z3 solver as a dependency.


Your First Analysis
-------------------

Let's analyze a simple function:

.. code-block:: python

   from pyspectre import analyze

   def calculate_average(total, count):
       return total / count

   result = analyze(calculate_average, {"total": "int", "count": "int"})

   if result.has_issues():
       print("Issues found!")
       for issue in result.issues:
           print(issue.format())

Output:

.. code-block:: text

   Issues found!
   [DIVISION_BY_ZERO] at line 2
     Possible division by zero: total / count
     Counterexample: count = 0


Understanding Results
---------------------

The ``analyze()`` function returns an ``ExecutionResult`` with:

- ``issues``: List of detected problems
- ``paths_explored``: Number of execution paths explored
- ``coverage``: Set of bytecode instructions covered
- ``format_summary()``: Human-readable summary


Safe Code Patterns
------------------

PySpectre recognizes safe patterns. This function won't report issues:

.. code-block:: python

   def safe_divide(x, y):
       if y != 0:
           return x / y
       return 0

   result = analyze(safe_divide, {"x": "int", "y": "int"})
   print(result.has_issues())  # False


Using the CLI
-------------

You can also use PySpectre from the command line:

.. code-block:: bash

   # Analyze a function in a file
   pyspectre myfile.py -f my_function

   # Output as JSON
   pyspectre myfile.py -f my_function --format json

   # Specify parameter types
   pyspectre myfile.py -f my_function --args x=int y=str


Next Steps
----------

- Read the :doc:`userguide` for detailed usage
- Explore the :doc:`api` reference
- Learn about :doc:`advanced` features
