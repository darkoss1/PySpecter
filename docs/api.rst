API Reference
=============

This section documents the public API of PySpectre.


Main Functions
--------------

.. autofunction:: pyspectre.analyze

.. autofunction:: pyspectre.analyze_file

.. autofunction:: pyspectre.quick_check

.. autofunction:: pyspectre.check_division_by_zero

.. autofunction:: pyspectre.check_assertions

.. autofunction:: pyspectre.format_result


Core Classes
------------

ExecutionResult
~~~~~~~~~~~~~~~

.. autoclass:: pyspectre.ExecutionResult
   :members:
   :undoc-members:

Issue
~~~~~

.. autoclass:: pyspectre.Issue
   :members:
   :undoc-members:

IssueKind
~~~~~~~~~

.. autoclass:: pyspectre.IssueKind
   :members:
   :undoc-members:


Execution
---------

SymbolicExecutor
~~~~~~~~~~~~~~~~

.. autoclass:: pyspectre.execution.executor.SymbolicExecutor
   :members:
   :undoc-members:

ExecutionConfig
~~~~~~~~~~~~~~~

.. autoclass:: pyspectre.execution.executor.ExecutionConfig
   :members:
   :undoc-members:


Types
-----

SymbolicValue
~~~~~~~~~~~~~

.. autoclass:: pyspectre.core.types.SymbolicValue
   :members:
   :undoc-members:

SymbolicString
~~~~~~~~~~~~~~

.. autoclass:: pyspectre.core.types.SymbolicString
   :members:
   :undoc-members:

SymbolicList
~~~~~~~~~~~~

.. autoclass:: pyspectre.core.types.SymbolicList
   :members:
   :undoc-members:


Analysis
--------

DetectorRegistry
~~~~~~~~~~~~~~~~

.. autoclass:: pyspectre.analysis.detectors.DetectorRegistry
   :members:
   :undoc-members:

PathManager
~~~~~~~~~~~

.. autoclass:: pyspectre.analysis.path_manager.PathManager
   :members:
   :undoc-members:


Formatters
----------

.. autofunction:: pyspectre.reporting.formatters.format_result

.. autoclass:: pyspectre.reporting.formatters.TextFormatter
   :members:

.. autoclass:: pyspectre.reporting.formatters.JSONFormatter
   :members:

.. autoclass:: pyspectre.reporting.formatters.HTMLFormatter
   :members:

.. autoclass:: pyspectre.reporting.formatters.MarkdownFormatter
   :members:
