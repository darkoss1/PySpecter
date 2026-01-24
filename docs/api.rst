API Reference
=============

This section documents the public API of Shadow VM.


Main Functions
--------------

.. autofunction:: shadow_vm.analyze

.. autofunction:: shadow_vm.analyze_file

.. autofunction:: shadow_vm.quick_check

.. autofunction:: shadow_vm.check_division_by_zero

.. autofunction:: shadow_vm.check_assertions

.. autofunction:: shadow_vm.format_result


Core Classes
------------

ExecutionResult
~~~~~~~~~~~~~~~

.. autoclass:: shadow_vm.ExecutionResult
   :members:
   :undoc-members:

Issue
~~~~~

.. autoclass:: shadow_vm.Issue
   :members:
   :undoc-members:

IssueKind
~~~~~~~~~

.. autoclass:: shadow_vm.IssueKind
   :members:
   :undoc-members:


Execution
---------

SymbolicExecutor
~~~~~~~~~~~~~~~~

.. autoclass:: shadow_vm.execution.executor.SymbolicExecutor
   :members:
   :undoc-members:

ExecutionConfig
~~~~~~~~~~~~~~~

.. autoclass:: shadow_vm.execution.executor.ExecutionConfig
   :members:
   :undoc-members:


Types
-----

SymbolicValue
~~~~~~~~~~~~~

.. autoclass:: shadow_vm.core.types.SymbolicValue
   :members:
   :undoc-members:

SymbolicString
~~~~~~~~~~~~~~

.. autoclass:: shadow_vm.core.types.SymbolicString
   :members:
   :undoc-members:

SymbolicList
~~~~~~~~~~~~

.. autoclass:: shadow_vm.core.types.SymbolicList
   :members:
   :undoc-members:


Analysis
--------

DetectorRegistry
~~~~~~~~~~~~~~~~

.. autoclass:: shadow_vm.analysis.detectors.DetectorRegistry
   :members:
   :undoc-members:

PathManager
~~~~~~~~~~~

.. autoclass:: shadow_vm.analysis.path_manager.PathManager
   :members:
   :undoc-members:


Formatters
----------

.. autofunction:: shadow_vm.reporting.formatters.format_result

.. autoclass:: shadow_vm.reporting.formatters.TextFormatter
   :members:

.. autoclass:: shadow_vm.reporting.formatters.JSONFormatter
   :members:

.. autoclass:: shadow_vm.reporting.formatters.HTMLFormatter
   :members:

.. autoclass:: shadow_vm.reporting.formatters.MarkdownFormatter
   :members:
